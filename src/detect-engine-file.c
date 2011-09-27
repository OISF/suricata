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
static int DetectFileInspect(ThreadVars *tv, DetectEngineThreadCtx *det_ctx, Flow *f, Signature *s, FileContainer *ffc) {
    SigMatch *sm = NULL;
    int r = 0;
    int match = 0;

    SCLogDebug("file inspection...");

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

            /* run the file match functions. */
            for (sm = s->sm_lists[DETECT_SM_LIST_FILEMATCH]; sm != NULL; sm = sm->next) {
                SCLogDebug("sm %p, sm->next %p", sm, sm->next);

                if (sigmatch_table[sm->type].AppLayerMatch != NULL) {
                    match = sigmatch_table[sm->type].
                        AppLayerMatch(tv, det_ctx, f, 0, (void *)file, s, sm);
                    if (match == 0) {
                        r = 2;
                        break;
                    } else if (sm->next == NULL) {
                        r = 1;
                        break;
                    }
                }
            }

            if (r == 1)
                break;

            /* if this is a filestore sig, and the sig can't match
             * return 3 so we can distinguish */
            if (s->init_flags & SIG_FLAG_FILESTORE && r == 2)
                r = 3;
        }
    }

    SCReturnInt(r);
}

int DetectFileInspectHttp(ThreadVars *tv, DetectEngineThreadCtx *det_ctx, Flow *f, Signature *s, void *alstate) {
    SCEnter();

    int r = 0;
    HtpState *htp_state = NULL;
    size_t idx = 0;
    size_t start_tx = 0;
    size_t end_tx = 0;
    int match = 0;

    htp_state = (HtpState *)alstate;
    if (htp_state == NULL) {
        SCLogDebug("no HTTP state");
        SCReturnInt(0);
    }

    /* locking the flow, we will inspect the htp state */
    SCMutexLock(&f->m);
    if (htp_state->connp != NULL && htp_state->connp->conn != NULL)
    {
        start_tx = AppLayerTransactionGetInspectId(f);
        end_tx = list_size(htp_state->connp->conn->transactions);

    }
    SCMutexUnlock(&f->m);

    for (idx = start_tx ; idx < end_tx; idx++)
    {
        /* inspect files for this transaction */
        det_ctx->tx_id = (uint16_t)idx;

        match = DetectFileInspect(tv, det_ctx, f, s, htp_state->files);
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

    SCReturnInt(r);
}
