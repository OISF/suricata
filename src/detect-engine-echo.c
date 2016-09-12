/* Copyright (C) 2015 Open Information Security Foundation
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

/*
 * TODO: Update your name below and in detect-engine-echo.h.
 * TODO: Update description in the \file section below.
 * TODO: Remove SCLogNotice statements or convert to debug.
 */

/**
 * \file
 *
 * \author FirstName LastName <yourname@domain>
 *
 * Implement buffer inspection on the decoded application layer
 * content buffers.
 */

#include "suricata-common.h"
#include "stream.h"
#include "detect-engine-content-inspection.h"

#include "app-layer-echo.h"

int DetectEngineInspectEchoBuffer(ThreadVars *tv, DetectEngineCtx *de_ctx,
    DetectEngineThreadCtx *det_ctx, Signature *s, Flow *f, uint8_t flags,
    void *alstate, void *txv, uint64_t tx_id)
{
    EchoTransaction *tx = (EchoTransaction *)txv;
    int ret = 0;

    if (flags & STREAM_TOSERVER && tx->request_buffer != NULL) {
        ret = DetectEngineContentInspection(de_ctx, det_ctx, s,
            s->sm_lists[DETECT_SM_LIST_ECHO_BUFFER_MATCH], f,
            tx->request_buffer, tx->request_buffer_len, 0,
            DETECT_ENGINE_CONTENT_INSPECTION_MODE_ECHO_BUFFER, NULL);
    }
    else if (flags & STREAM_TOCLIENT && tx->response_buffer != NULL) {
        ret = DetectEngineContentInspection(de_ctx, det_ctx, s,
            s->sm_lists[DETECT_SM_LIST_ECHO_BUFFER_MATCH], f,
            tx->response_buffer, tx->response_buffer_len, 0,
            DETECT_ENGINE_CONTENT_INSPECTION_MODE_ECHO_BUFFER, NULL);
    }

    SCLogNotice("Returning %d.", ret);
    return ret;
}
