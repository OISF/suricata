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

#include "suricata.h"
#include "suricata-common.h"
#include "decode.h"
#include "threads.h"

#include "util-print.h"
#include "util-pool.h"
#include "util-radix-tree.h"

#include "stream-tcp-private.h"
#include "stream-tcp-reassemble.h"
#include "stream-tcp.h"
#include "stream.h"

#include "app-layer-protos.h"
#include "app-layer-parser.h"
#include "app-layer-htp.h"
#include "app-layer-htp-body.h"
#include "app-layer-htp-mem.h"

#include "util-spm.h"
#include "util-debug.h"
#include "app-layer-htp-file.h"
#include "util-time.h"

#include "util-unittest.h"
#include "util-unittest-helper.h"
#include "flow-util.h"

#include "detect-engine.h"
#include "detect-engine-state.h"
#include "detect-parse.h"

#include "conf.h"

#include "util-memcmp.h"

static StreamingBufferConfig default_cfg = { 0, 3072, HTPCalloc, HTPRealloc, HTPFree };

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
        const StreamingBufferConfig *cfg = hcfg ? &hcfg->sbcfg : &default_cfg;
        body->sb = StreamingBufferInit(cfg);
        if (body->sb == NULL)
            SCReturnInt(-1);
    }

    /* New chunk */
    bd = (HtpBodyChunk *)HTPCalloc(1, sizeof(HtpBodyChunk));
    if (bd == NULL) {
        SCReturnInt(-1);
    }

    if (StreamingBufferAppend(body->sb, &bd->sbseg, data, len) != 0) {
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
void HtpBodyPrint(HtpBody *body)
{
    if (SCLogDebugEnabled()||1) {
        SCEnter();

        if (body->first == NULL)
            return;

        HtpBodyChunk *cur = NULL;
        SCLogDebug("--- Start body chunks at %p ---", body);
        printf("--- Start body chunks at %p ---\n", body);
        for (cur = body->first; cur != NULL; cur = cur->next) {
            const uint8_t *data = NULL;
            uint32_t data_len = 0;
            StreamingBufferSegmentGetData(body->sb, &cur->sbseg, &data, &data_len);
            SCLogDebug("Body %p; data %p, len %"PRIu32, body, data, data_len);
            printf("Body %p; data %p, len %"PRIu32"\n", body, data, data_len);
            PrintRawDataFp(stdout, data, data_len);
        }
        SCLogDebug("--- End body chunks at %p ---", body);
    }
}

/**
 * \brief Free the information held in the request body
 * \param body pointer to the HtpBody holding the list
 * \retval none
 */
void HtpBodyFree(HtpBody *body)
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

    StreamingBufferFree(body->sb);
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

    /* get the configured inspect sizes. Default to response values */
    uint32_t min_size = state->cfg->response.inspect_min_size;
    uint32_t window = state->cfg->response.inspect_window;

    if (direction == STREAM_TOSERVER) {
        min_size = state->cfg->request.inspect_min_size;
        window = state->cfg->request.inspect_window;
    }

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
        StreamingBufferSlideToOffset(body->sb, left_edge);
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
