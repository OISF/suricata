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
#include "detect-engine-hhd.h"
#include "detect-engine-hrhd.h"
#include "detect-engine-hmd.h"
#include "detect-engine-hcd.h"
#include "detect-engine-hrud.h"
#include "detect-engine-dcepayload.h"

#include "stream-tcp.h"
#include "stream-tcp-private.h"
#include "stream-tcp-reassemble.h"

#include "app-layer-parser.h"
#include "app-layer-protos.h"
#include "app-layer-htp.h"
#include "app-layer-smb.h"
#include "app-layer-dcerpc-common.h"
#include "app-layer-dcerpc.h"

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
 *
 *  \note flow is not locked at this time
 */
static int DetectFileInspect(ThreadVars *tv, DetectEngineThreadCtx *det_ctx,
        Flow *f, Signature *s, uint8_t flags, FileContainer *ffc)
{
    SigMatch *sm = NULL;
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
                SCLogDebug("file->txid < det_ctx->tx_id == %u < %u", file->txid, det_ctx->tx_id);
                continue;
            }

            if (file->txid > det_ctx->tx_id) {
                SCLogDebug("file->txid > det_ctx->tx_id == %u > %u", file->txid, det_ctx->tx_id);
                break;
            }

            if (s->file_flags & FILE_SIG_NEED_FILENAME && file->name == NULL) {
                SCLogDebug("sig needs filename, but we don't have any");
                r = 0;
                break;
            }

            if (s->file_flags & FILE_SIG_NEED_MAGIC && file->chunks_head == NULL) {
                SCLogDebug("sig needs file content, but we don't have any");
                r = 0;
                break;
            }

            if (s->file_flags & FILE_SIG_NEED_FILECONTENT && file->chunks_head == NULL) {
                SCLogDebug("sig needs file content, but we don't have any");
                r = 0;
                break;
            }

            if (s->file_flags & FILE_SIG_NEED_MD5 && (!(file->flags & FILE_MD5))) {
                SCLogDebug("sig needs file md5, but we don't have any");
                r = 0;
                break;
            }

            /* run the file match functions. */
            for (sm = s->sm_lists[DETECT_SM_LIST_FILEMATCH]; sm != NULL; sm = sm->next) {
                SCLogDebug("sm %p, sm->next %p", sm, sm->next);

                if (sigmatch_table[sm->type].AppLayerMatch != NULL) {
                    match = sigmatch_table[sm->type].
                        AppLayerMatch(tv, det_ctx, f, flags, (void *)file, s, sm);
                    if (match == 0) {
                        r = 2;
                        break;
                    } else if (sm->next == NULL) {
                        r = 1;
                        break;
                    }
                }
            }

            /* continue inspection for other files as we may want to store
             * those as well. We'll return 1 (match) regardless of their
             * results though */
            if (r == 1)
                store_r = 1;

            /* if this is a filestore sig, and the sig can't match
             * return 3 so we can distinguish */
            if (s->flags & SIG_FLAG_FILESTORE && r == 2)
                r = 3;

            /* continue, this file may (or may not) be unable to match
             * maybe we have more that can :) */
        }
    } else {
        /* if we have a filestore sm with a scope > file (so tx, ssn) we
         * run it here */
        sm = s->sm_lists[DETECT_SM_LIST_FILEMATCH];
        if (sm != NULL && sm->next == NULL && sm->type == DETECT_FILESTORE &&
                sm->ctx != NULL)
        {
            DetectFilestoreData *fd = sm->ctx;
            if (fd->scope > FILESTORE_SCOPE_DEFAULT) {
                match = sigmatch_table[sm->type].
                    AppLayerMatch(tv, det_ctx, f, flags, NULL, s, sm);
                if (match == 1) {
                    r = 1;
                }
            }
        }
    }

    if (store_r == 1)
        r = 1;
    SCReturnInt(r);
}

/**
 *  \brief Inspect the file inspecting keywords against the HTTP transactions.
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
int DetectFileInspectHttp(ThreadVars *tv, DetectEngineThreadCtx *det_ctx, Flow *f, Signature *s, void *alstate, uint8_t flags) {
    SCEnter();

    int r = 0;
    HtpState *htp_state = NULL;
    int idx = 0;
    int start_tx = 0;
    int end_tx = 0;
    int match = 0;
    FileContainer *ffc;

    /* locking the flow, we will inspect the htp state, files + we will set
     * magic, so need a WRITE lock */
    FLOWLOCK_WRLOCK(f);

    htp_state = (HtpState *)alstate;
    if (htp_state == NULL) {
        SCLogDebug("no HTTP state");
        goto end;
    }

    if (flags & STREAM_TOCLIENT)
        ffc = htp_state->files_tc;
    else
        ffc = htp_state->files_ts;

    if (htp_state->connp != NULL && htp_state->connp->conn != NULL)
    {
        start_tx = AppLayerTransactionGetInspectId(f);
        if (start_tx == -1) {
            goto end;
        }

        /* tx cnt is incremented after request finishes, so we need to inspect
         * response one before the lowest. */
        if ((flags & STREAM_TOCLIENT) && start_tx > 0)
            start_tx--;
        end_tx = (int)list_size(htp_state->connp->conn->transactions);
    }

    for (idx = start_tx ; idx < end_tx; idx++)
    {
        /* inspect files for this transaction */
        det_ctx->tx_id = (uint16_t)idx;

        match = DetectFileInspect(tv, det_ctx, f, s, flags, ffc);
        if (match == 1) {
            r = 1;
        } else if (match == 2) {
            if (r != 1) {
                SCLogDebug("sid %u can't match on this transaction", s->id);
                r = 2;
            }
        } else if (match == 3) {
            if (r != 1) {
                SCLogDebug("sid %u can't match on this transaction (filestore sig)", s->id);
                r = 3;
            }
        }
    }

end:
    FLOWLOCK_UNLOCK(f);
    SCReturnInt(r);
}
