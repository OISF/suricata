/* Copyright (C) 2007-2017 Open Information Security Foundation
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
 * \ingroup httplayer
 *
 * @{
 */

#include "suricata-common.h"
#include "threads.h"
#include "decode.h"

#include "detect.h"
#include "detect-parse.h"
#include "detect-engine.h"
#include "detect-engine-mpm.h"
#include "detect-engine-state.h"
#include "detect-engine-prefilter.h"
#include "detect-engine-content-inspection.h"
#include "detect-content.h"
#include "detect-pcre.h"

#include "flow.h"
#include "flow-var.h"
#include "flow-util.h"

#include "util-debug.h"
#include "util-unittest.h"
#include "util-unittest-helper.h"
#include "util-spm.h"
#include "util-print.h"

#include "app-layer.h"
#include "app-layer-parser.h"

#include "app-layer-htp.h"
#include "detect-http-header.h"
#include "stream-tcp.h"

#include "util-print.h"

#include "detect-http-header-common.h"

static inline int CreateSpace(HttpHeaderThreadData *td, uint64_t size);

void *HttpHeaderThreadDataInit(void *data)
{
    HttpHeaderThreadData *td = SCCalloc(1, sizeof(*td));
    if (td != NULL) {
        if (data == NULL) {
            td->tx_step = 4;
            td->size_step = 512;
        } else {
            HttpHeaderThreadDataConfig *c = data;
            td->tx_step = c->tx_step;
            td->size_step = c->size_step;
        }

        /* initialize minimal buffers */
        (void)CreateSpace(td, 1);
        int i;
        for (i = 0; i < td->buffers_size; i++) {
            (void)HttpHeaderExpandBuffer(td, &td->buffers[i], 1);
        }
    }
    return td;
}

void HttpHeaderThreadDataFree(void *data)
{
    HttpHeaderThreadData *hdrnames = data;

    int i;
    for (i = 0; i < hdrnames->buffers_size; i++) {
        if (hdrnames->buffers[i].buffer)
            SCFree(hdrnames->buffers[i].buffer);
        if (hdrnames->buffers[i].size) {
            SCLogDebug("hdrnames->buffers[%d].size %u (%u)",
                    i, hdrnames->buffers[i].size, hdrnames->buffers_size);
        }
    }
    SCFree(hdrnames->buffers);
    SCFree(hdrnames);
}

static void Reset(HttpHeaderThreadData *hdrnames, uint64_t tick)
{
    uint16_t i;
    for (i = 0; i < hdrnames->buffers_list_len; i++) {
        hdrnames->buffers[i].len = 0;
    }
    hdrnames->buffers_list_len = 0;
    hdrnames->start_tx_id = 0;
    hdrnames->tick = tick;
}

static inline int CreateSpace(HttpHeaderThreadData *td, uint64_t size)
{
    if (size >= SHRT_MAX)
        return -1;

    if (size > td->buffers_size) {
        uint16_t extra = td->tx_step;
        while (td->buffers_size + extra < size) {
            extra += td->tx_step;
        }
        SCLogDebug("adding %u to the buffer", extra);

        void *ptmp = SCRealloc(td->buffers,
                         (td->buffers_size + extra) * sizeof(HttpHeaderBuffer));
        if (ptmp == NULL) {
            SCFree(td->buffers);
            td->buffers = NULL;
            td->buffers_size = 0;
            td->buffers_list_len = 0;
            return -1;
        }
        td->buffers = ptmp;
        memset(td->buffers + td->buffers_size, 0, extra * sizeof(HttpHeaderBuffer));
        td->buffers_size += extra;
    }
    return 0;
}

int HttpHeaderExpandBuffer(HttpHeaderThreadData *td,
        HttpHeaderBuffer *buf, uint32_t size)
{
    size_t extra = td->size_step;
    while ((buf->size + extra) < (size + buf->len)) {
        extra += td->size_step;
    }
    SCLogDebug("adding %"PRIuMAX" to the buffer", (uintmax_t)extra);

    uint8_t *new_buffer = SCRealloc(buf->buffer, buf->size + extra);
    if (unlikely(new_buffer == NULL)) {
        buf->len = 0;
        return -1;
    }
    buf->buffer = new_buffer;
    buf->size += extra;
    return 0;
}

HttpHeaderBuffer *HttpHeaderGetBufferSpaceForTXID(DetectEngineThreadCtx *det_ctx,
        Flow *f, uint8_t flags, uint64_t tx_id, const int keyword_id,
        HttpHeaderThreadData **ret_hdr_td)
{
    int index = 0;
    *ret_hdr_td = NULL;

    HttpHeaderThreadData *hdr_td =
        DetectThreadCtxGetGlobalKeywordThreadCtx(det_ctx, keyword_id);
    if (hdr_td == NULL)
        return NULL;
    if (hdr_td->tick != det_ctx->ticker)
        Reset(hdr_td, det_ctx->ticker);
    *ret_hdr_td = hdr_td;

    if (hdr_td->buffers_list_len == 0) {
        /* get the inspect id to use as a 'base id' */
        uint64_t base_inspect_id = AppLayerParserGetTransactionInspectId(f->alparser, flags);
        BUG_ON(base_inspect_id > tx_id);
        /* see how many space we need for the current tx_id */
        uint64_t txs = (tx_id - base_inspect_id) + 1;
        if (CreateSpace(hdr_td, txs) < 0)
            return NULL;

        index = (tx_id - base_inspect_id);
        hdr_td->start_tx_id = base_inspect_id;
        hdr_td->buffers_list_len = txs;
    } else {
        /* tx fits in our current buffers */
        if ((tx_id - hdr_td->start_tx_id) < hdr_td->buffers_list_len) {
            /* if we previously reassembled, return that buffer */
            if (hdr_td->buffers[(tx_id - hdr_td->start_tx_id)].len != 0) {
                return &hdr_td->buffers[(tx_id - hdr_td->start_tx_id)];
            }
            /* otherwise fall through */
        } else {
            /* not enough space, lets expand */
            uint64_t txs = (tx_id - hdr_td->start_tx_id) + 1;
            if (CreateSpace(hdr_td, txs) < 0)
                return NULL;

            hdr_td->buffers_list_len = txs;
        }
        index = (tx_id - hdr_td->start_tx_id);
    }
    HttpHeaderBuffer *buf = &hdr_td->buffers[index];
    return buf;
}
