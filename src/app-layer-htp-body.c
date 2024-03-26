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
 * \author Gurvinder Singh <gurvindersinghdahiya@gmail.com>
 * \author Pablo Rincon <pablo.rincon.crespo@gmail.com>
 * \author Brian Rectanus <brectanu@gmail.com>
 *
 * This file provides a HTTP protocol support for the engine using HTP library.
 */

#include "suricata-common.h"
#include "app-layer-htp.h"
#include "app-layer-htp-mem.h"
#include "app-layer-htp-body.h"
#include "util-streaming-buffer.h"
#include "util-print.h"

extern StreamingBufferConfig htp_sbcfg;

/**
 * \brief Append a chunk of body to the HtpBody struct
 *
 * \param body pointer to the HtpBody holding the list
 * \param data pointer to the data of the chunk
 * \param len length of the chunk pointed by data
 *
 * \retval 0 ok
 * \retval -1 error
 */
int HtpBodyAppendChunk(const HTPCfgDir *hcfg, HtpBody *body,
                       const uint8_t *data, uint32_t len)
{
    SCEnter();

    HtpBodyChunk *bd = NULL;

    if (len == 0 || data == NULL) {
        SCReturnInt(0);
    }

    if (body->sb == NULL) {
        body->sb = StreamingBufferInit(&htp_sbcfg);
        if (body->sb == NULL)
            SCReturnInt(-1);
    }

    /* New chunk */
    bd = (HtpBodyChunk *)HTPCalloc(1, sizeof(HtpBodyChunk));
    if (bd == NULL) {
        SCReturnInt(-1);
    }

    if (StreamingBufferAppend(body->sb, &htp_sbcfg, &bd->sbseg, data, len) != 0) {
        HTPFree(bd, sizeof(HtpBodyChunk));
        SCReturnInt(-1);
    }

    if (body->first == NULL) {
        body->first = body->last = bd;
    } else {
        body->last->next = bd;
        body->last = bd;
    }
    body->content_len_so_far += len;

    SCLogDebug("body %p", body);

    SCReturnInt(0);
}

/**
 * \brief Print the information and chunks of a Body
 * \param body pointer to the HtpBody holding the list
 * \retval none
 */

/**
 * \brief Free the information held in the request body
 * \param body pointer to the HtpBody holding the list
 * \retval none
 */
void HtpBodyFree(const HTPCfgDir *hcfg, HtpBody *body)
{
    SCEnter();

    SCLogDebug("removing chunks of body %p", body);

    HtpBodyChunk *cur = NULL;
    HtpBodyChunk *prev = NULL;

    prev = body->first;
    while (prev != NULL) {
        cur = prev->next;
        HTPFree(prev, sizeof(HtpBodyChunk));
        prev = cur;
    }
    body->first = body->last = NULL;

    StreamingBufferFree(body->sb, &htp_sbcfg);
}

/**
 * \brief Free request body chunks that are already fully parsed.
 *
 * \param state htp_state, with reference to our config
 * \param body the body to prune
 * \param direction STREAM_TOSERVER (request), STREAM_TOCLIENT (response)
 *
 * \retval none
 */
void HtpBodyPrune(HtpState *state, HtpBody *body, int direction)
{
    SCEnter();

    if (body == NULL || body->first == NULL) {
        SCReturn;
    }

    if (body->body_parsed == 0) {
        SCReturn;
    }

    const HTPCfgDir *cfg =
            (direction == STREAM_TOCLIENT) ? &state->cfg->response : &state->cfg->request;
    uint32_t min_size = cfg->inspect_min_size;
    uint32_t window = cfg->inspect_window;
    uint64_t max_window = ((min_size > window) ? min_size : window);
    uint64_t in_flight = body->content_len_so_far - body->body_inspected;

    /* Special case. If body_inspected is not being updated, we make sure that
     * we prune the body. We allow for some extra size/room as we may be called
     * multiple times on uninspected body chunk additions if a large block of
     * data was ack'd at once. Want to avoid pruning before inspection. */
    if (in_flight > (max_window * 3)) {
        body->body_inspected = body->content_len_so_far - max_window;
    } else if (body->body_inspected < max_window) {
        SCReturn;
    }

    uint64_t left_edge = body->body_inspected;
    if (left_edge <= min_size || left_edge <= window)
        left_edge = 0;
    if (left_edge)
        left_edge -= window;

    if (left_edge) {
        SCLogDebug("sliding body to offset %"PRIu64, left_edge);
        StreamingBufferSlideToOffset(body->sb, &htp_sbcfg, left_edge);
    }

    SCLogDebug("pruning chunks of body %p", body);

    HtpBodyChunk *cur = body->first;
    while (cur != NULL) {
        HtpBodyChunk *next = cur->next;
        SCLogDebug("cur %p", cur);

        if (!StreamingBufferSegmentIsBeforeWindow(body->sb, &cur->sbseg)) {
            SCLogDebug("not removed");
            break;
        }

        body->first = next;
        if (body->last == cur) {
            body->last = next;
        }

        HTPFree(cur, sizeof(HtpBodyChunk));

        cur = next;
        SCLogDebug("removed");
    }

    SCReturn;
}
