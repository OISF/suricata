/* Copyright (C) 2007-2010 Open Information Security Foundation
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

/** \file
 *
 *  \author Victor Julien <victor@inliniac.net>
 *  \author Pablo Rincon Crespo <pablo.rincon.crespo@gmail.com>
 *
 *  Based on detect-engine-payload.c
 */

#include "suricata-common.h"
#include "suricata.h"
#include "decode.h"

#include "detect.h"
#include "detect-uricontent.h"
#include "detect-pcre.h"
#include "detect-isdataat.h"
#include "detect-bytetest.h"
#include "detect-bytejump.h"

#include "util-spm.h"
#include "util-debug.h"
#include "util-print.h"
#include "flow.h"
#include "detect-flow.h"
#include "flow-var.h"
#include "threads.h"
#include "flow-alert-sid.h"

#include "stream-tcp.h"
#include "stream.h"
#include "app-layer-parser.h"

#include "util-unittest.h"
#include "util-unittest-helper.h"
#include "app-layer.h"
#include "app-layer-htp.h"
#include "app-layer-protos.h"

/** \brief Run the actual payload match function for uricontent
 *
 *  For accounting the last match in relative matching the
 *  det_ctx->uricontent_payload_offset int is used.
 *
 *  \param de_ctx Detection engine context
 *  \param det_ctx Detection engine thread context
 *  \param s Signature to inspect
 *  \param sm SigMatch to inspect
 *  \param payload ptr to the uricontent payload to inspect
 *  \param payload_len length of the uricontent payload
 *
 *  \retval 0 no match
 *  \retval 1 match
 */
static int DoInspectPacketUri(DetectEngineCtx *de_ctx,
        DetectEngineThreadCtx *det_ctx, Signature *s, SigMatch *sm,
        uint8_t *payload, uint32_t payload_len)
{
    SCEnter();

    if (sm == NULL) {
        SCReturnInt(0);
    }

    if (sm->type == DETECT_URICONTENT) {
        if (payload_len == 0) {
            SCReturnInt(0);
        }

        DetectUricontentData *ud = NULL;
        ud = (DetectUricontentData *)sm->ctx;
        SCLogDebug("inspecting content %"PRIu32" payload_len %"PRIu32, ud->id, payload_len);

        /* rule parsers should take care of this */
        BUG_ON(ud->depth != 0 && ud->depth <= ud->offset);

        /* search for our pattern, checking the matches recursively.
         * if we match we look for the next SigMatch as well */
        uint8_t *found = NULL;
        uint32_t offset = 0;
        uint32_t depth = payload_len;
        uint32_t prev_offset = 0; /**< used in recursive searching */

        do {
            if (ud->flags & DETECT_URICONTENT_DISTANCE ||
                ud->flags & DETECT_URICONTENT_WITHIN) {
                SCLogDebug("det_ctx->uricontent_payload_offset %"PRIu32, det_ctx->uricontent_payload_offset);

                offset = det_ctx->uricontent_payload_offset;
                depth = payload_len;

                if (ud->flags & DETECT_URICONTENT_DISTANCE) {
                    if (ud->distance < 0 && (uint32_t)(abs(ud->distance)) > offset)
                        offset = 0;
                    else
                        offset += ud->distance;

                    SCLogDebug("ud->distance %"PRIi32", offset %"PRIu32", depth %"PRIu32,
                        ud->distance, offset, depth);
                }

                if (ud->flags & DETECT_URICONTENT_WITHIN) {
                    if ((int32_t)depth > (int32_t)(det_ctx->uricontent_payload_offset + ud->within)) {
                        depth = det_ctx->uricontent_payload_offset + ud->within;
                    }

                    SCLogDebug("ud->within %"PRIi32", det_ctx->uricontent_payload_offset %"PRIu32", depth %"PRIu32,
                        ud->within, det_ctx->uricontent_payload_offset, depth);
                }

                if (ud->depth != 0) {
                    if ((ud->depth + det_ctx->uricontent_payload_offset) < depth) {
                        depth = det_ctx->uricontent_payload_offset + ud->depth;
                    }

                    SCLogDebug("ud->depth %"PRIu32", depth %"PRIu32, ud->depth, depth);
                }

                if (ud->offset > offset) {
                    offset = ud->offset;
                    SCLogDebug("setting offset %"PRIu32, offset);
                }
            } else { /* implied no relative matches */
                /* set depth */
                if (ud->depth != 0) {
                    depth = ud->depth;
                }

                /* set offset */
                offset = ud->offset;
            }

            /* update offset with prev_offset if we're searching for
             * matches after the first occurence. */
            SCLogDebug("offset %"PRIu32", prev_offset %"PRIu32, prev_offset, depth);
            offset += prev_offset;

            SCLogDebug("offset %"PRIu32", depth %"PRIu32, offset, depth);

            if (depth > payload_len)
                depth = payload_len;

            /* if offset is bigger than depth we can never match on a pattern.
             * We can however, "match" on a negated pattern. */
            if (offset > depth || depth == 0) {
                if (ud->flags & DETECT_URICONTENT_NEGATED) {
                    goto match;
                } else {
                    SCReturnInt(0);
                }
            }

            uint8_t *spayload = payload + offset;
            uint32_t spayload_len = depth - offset;
            uint32_t match_offset = 0;
            SCLogDebug("spayload_len %"PRIu32, spayload_len);
            BUG_ON(spayload_len > payload_len);

            //PrintRawDataFp(stdout,ud->uricontent,ud->uricontent_len);
            //PrintRawDataFp(stdout,spayload,spayload_len);

            /* do the actual search with boyer moore precooked ctx */
            if (ud->flags & DETECT_URICONTENT_NOCASE)
                found = BoyerMooreNocase(ud->uricontent, ud->uricontent_len, spayload, spayload_len, ud->bm_ctx->bmGs, ud->bm_ctx->bmBc);
            else
                found = BoyerMoore(ud->uricontent, ud->uricontent_len, spayload, spayload_len, ud->bm_ctx->bmGs, ud->bm_ctx->bmBc);

            /* next we evaluate the result in combination with the
             * negation flag. */
            SCLogDebug("found %p ud negated %s", found, ud->flags & DETECT_URICONTENT_NEGATED ? "true" : "false");

            if (found == NULL && !(ud->flags & DETECT_URICONTENT_NEGATED)) {
                SCReturnInt(0);
            } else if (found == NULL && ud->flags & DETECT_URICONTENT_NEGATED) {
                goto match;
            } else if (found != NULL && ud->flags & DETECT_URICONTENT_NEGATED) {
                match_offset = (uint32_t)((found - payload) + ud->uricontent_len);
                SCLogDebug("uricontent %"PRIu32" matched at offset %"PRIu32", but negated so no match", ud->id, match_offset);
                SCReturnInt(0);
            } else {
                match_offset = (uint32_t)((found - payload) + ud->uricontent_len);
                SCLogDebug("uricontent %"PRIu32" matched at offset %"PRIu32"", ud->id, match_offset);
                det_ctx->uricontent_payload_offset = match_offset;

                if (!(ud->flags & DETECT_URICONTENT_RELATIVE_NEXT)) {
                    SCLogDebug("no relative match coming up, so this is a match");
                    goto match;
                }

                BUG_ON(sm->next == NULL);
                SCLogDebug("uricontent %"PRIu32, ud->id);

                /* see if the next payload keywords match. If not, we will
                 * search for another occurence of this uricontent and see
                 * if the others match then until we run out of matches */
                int r = DoInspectPacketUri(de_ctx,det_ctx,s,sm->next, payload, payload_len);
                if (r == 1) {
                    SCReturnInt(1);
                }

                /* set the previous match offset to the start of this match + 1 */
                prev_offset += (match_offset - (ud->uricontent_len - 1));
                SCLogDebug("trying to see if there is another match after prev_offset %"PRIu32, prev_offset);
            }

        } while(1);
    } else {
        /* we should never get here, but bail out just in case */
        BUG_ON(1);
    }
    SCReturnInt(0);

match:
    /* this sigmatch matched, inspect the next one. If it was the last,
     * the payload portion of the signature matched. */
    if (sm->next != NULL) {
        int r = DoInspectPacketUri(de_ctx,det_ctx,s,sm->next, payload, payload_len);
        SCReturnInt(r);
    } else {
        SCReturnInt(1);
    }
}

/** \brief Do the content inspection & validation for a signature
 *
 *  \param de_ctx Detection engine context
 *  \param det_ctx Detection engine thread context
 *  \param s Signature to inspect
 *  \param sm SigMatch to inspect
 *  \param f Flow
 *  \param flags app layer flags
 *  \param state App layer state
 *
 *  \retval 0 no match
 *  \retval 1 match
 */
int DetectEngineInspectPacketUris(DetectEngineCtx *de_ctx,
        DetectEngineThreadCtx *det_ctx, Signature *s, Flow *f, uint8_t flags,
        void *alstate)
{
    SCEnter();
    SigMatch *sm = NULL;
    int r = 0;
    HtpState *htp_state = NULL;

    if (!(det_ctx->sgh->flags & SIG_GROUP_HAVEURICONTENT)) {
        SCLogDebug("no uricontent in sgh");
        SCReturnInt(0);
    }

    htp_state = (HtpState *)alstate;
    if (htp_state == NULL) {
        SCLogDebug("no HTTP state");
        SCReturnInt(0);
    }

    /* locking the flow, we will inspect the htp state */
    SCMutexLock(&f->m);

    if (htp_state->connp == NULL) {
        SCLogDebug("HTP state has no connp");
        goto end;
    }

    /* If we have the uricontent multi pattern matcher signatures in
       signature list, then search the received HTTP uri(s) in the htp
       state against those patterns */
    if (s->flags & SIG_FLAG_MPM_URI) {
        if (det_ctx->de_mpm_scanned_uri == FALSE) {
            uint32_t cnt = DetectUricontentInspectMpm(det_ctx, f, htp_state);

            /* only consider uri sigs if we've seen at least one match */
            /** \warning when we start supporting negated uri content matches
             * we need to update this check as well */
            if (cnt > 0) {
                det_ctx->de_have_httpuri = TRUE;
            }

            SCLogDebug("uricontent cnt %"PRIu32"", cnt);

            /* make sure we don't inspect this mpm again */
            det_ctx->de_mpm_scanned_uri = TRUE;

        }
    }

    /* if we don't have a uri, don't bother inspecting */
    if (det_ctx->de_have_httpuri == FALSE) {
        SCLogDebug("We don't have uri");
        goto end;
    }

    if (det_ctx->de_mpm_scanned_uri == TRUE) {
        if (det_ctx->pmq.pattern_id_bitarray != NULL) {
            /* filter out sigs that want pattern matches, but
             * have no matches */
            if (!(det_ctx->pmq.pattern_id_bitarray[(s->mpm_uripattern_id / 8)] & (1<<(s->mpm_uripattern_id % 8))) &&
                    (s->flags & SIG_FLAG_MPM_URI) && !(s->flags & SIG_FLAG_MPM_URI_NEG)) {
                SCLogDebug("mpm sig without matches (pat id %"PRIu32
                        " check in uri).", s->mpm_uripattern_id);
                goto end;
            }
        }
    }

    sm = s->umatch;

    det_ctx->uricontent_payload_offset = 0;

#ifdef DEBUG
    DetectUricontentData *co = (DetectUricontentData *)sm->ctx;
    SCLogDebug("co->id %"PRIu32, co->id);
#endif

    size_t idx = AppLayerTransactionGetInspectId(f);
    htp_tx_t *tx = NULL;

    for ( ; idx < list_size(htp_state->connp->conn->transactions); idx++)
    {
        tx = list_get(htp_state->connp->conn->transactions, idx);
        if (tx == NULL || tx->request_uri_normalized == NULL)
            continue;

        /* Inspect all the uricontents fetched on each
         * transaction at the app layer */
        r = DoInspectPacketUri(de_ctx, det_ctx, s, s->umatch,
                (uint8_t *) bstr_ptr(tx->request_uri_normalized),
                bstr_len(tx->request_uri_normalized));

        if (r == 1) {
            break;
        }
    }

    if (r < 1)
        r = 0;

end:
    SCMutexUnlock(&f->m);
    SCReturnInt(r);
}

