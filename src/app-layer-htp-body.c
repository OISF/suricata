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
#include "debug.h"
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

#include "util-spm.h"
#include "util-debug.h"
#include "app-layer-htp.h"
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
int HtpBodyAppendChunk(HtpTxUserData *htud, HtpBody *body, uint8_t *data, uint32_t len)
{
    SCEnter();

    HtpBodyChunk *bd = NULL;

    if (len == 0 || data == NULL) {
        SCReturnInt(0);
    }

    if (body->first == NULL) {
        /* New chunk */
        bd = (HtpBodyChunk *)HTPMalloc(sizeof(HtpBodyChunk));
        if (bd == NULL)
            goto error;

        bd->len = len;
        bd->stream_offset = 0;
        bd->next = NULL;
        bd->logged = 0;

        bd->data = HTPMalloc(len);
        if (bd->data == NULL) {
            goto error;
        }
        memcpy(bd->data, data, len);

        body->first = body->last = bd;

        body->content_len_so_far = len;
    } else {
        bd = (HtpBodyChunk *)HTPMalloc(sizeof(HtpBodyChunk));
        if (bd == NULL)
            goto error;

        bd->len = len;
        bd->stream_offset = body->content_len_so_far;
        bd->next = NULL;
        bd->logged = 0;

        bd->data = HTPMalloc(len);
        if (bd->data == NULL) {
            goto error;
        }
        memcpy(bd->data, data, len);

        body->last->next = bd;
        body->last = bd;

        body->content_len_so_far += len;
    }
    SCLogDebug("Body %p; data %p, len %"PRIu32, body, bd->data, (uint32_t)bd->len);

    SCReturnInt(0);

error:
    if (bd != NULL) {
        if (bd->data != NULL) {
            HTPFree(bd->data, bd->len);
        }
        HTPFree(bd, sizeof(HtpBodyChunk));
    }
    SCReturnInt(-1);
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
            SCLogDebug("Body %p; data %p, len %"PRIu32, body, cur->data, (uint32_t)cur->len);
            printf("Body %p; data %p, len %"PRIu32"\n", body, cur->data, (uint32_t)cur->len);
            PrintRawDataFp(stdout, (uint8_t*)cur->data, cur->len);
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

    if (body->first == NULL)
        return;

    SCLogDebug("Removing chunks of Body %p; data %p, len %"PRIu32, body,
            body->last->data, (uint32_t)body->last->len);

    HtpBodyChunk *cur = NULL;
    HtpBodyChunk *prev = NULL;

    prev = body->first;
    while (prev != NULL) {
        cur = prev->next;
        if (prev->data != NULL)
            HTPFree(prev->data, prev->len);
        HTPFree(prev, sizeof(HtpBodyChunk));
        prev = cur;
    }
    body->first = body->last = NULL;
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
    uint32_t min_size = state->cfg->response_inspect_min_size;
    uint32_t window = state->cfg->response_inspect_window;

    if (direction == STREAM_TOSERVER) {
        min_size = state->cfg->request_inspect_min_size;
        window = state->cfg->request_inspect_window;
    }

    if (body->body_inspected < (min_size > window) ? min_size : window) {
        SCReturn;
    }

    SCLogDebug("Pruning chunks of Body %p; data %p, len %"PRIu32, body,
            body->last->data, (uint32_t)body->last->len);

    HtpBodyChunk *cur = body->first;
    while (cur != NULL) {
        HtpBodyChunk *next = cur->next;

        SCLogDebug("cur->stream_offset %"PRIu64" + cur->len %u = %"PRIu64", "
                "body->body_parsed %"PRIu64, cur->stream_offset, cur->len,
                cur->stream_offset + cur->len, body->body_parsed);

        uint64_t left_edge = body->body_inspected;
        if (left_edge <= min_size || left_edge <= window)
            left_edge = 0;
        if (left_edge)
            left_edge -= window;

        if (cur->stream_offset + cur->len > left_edge) {
            break;
        }

        body->first = next;
        if (body->last == cur) {
            body->last = next;
        }

        if (cur->data != NULL) {
            HTPFree(cur->data, cur->len);
        }
        HTPFree(cur, sizeof(HtpBodyChunk));

        cur = next;
    }

    SCReturn;
}
