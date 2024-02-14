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

#include "detect-http-header-common.h"

void *HttpHeaderThreadDataInit(void *data)
{
    HttpHeaderThreadData *td = SCCalloc(1, sizeof(*td));
    if (td != NULL) {
        if (data == NULL) {
            td->size_step = 512;
        } else {
            HttpHeaderThreadDataConfig *c = data;
            td->size_step = c->size_step;
        }

        /* initialize minimal buffers */
        (void)HttpHeaderExpandBuffer(td, &td->buffer, 1);
    }
    return td;
}

void HttpHeaderThreadDataFree(void *data)
{
    HttpHeaderThreadData *hdrnames = data;
    SCFree(hdrnames->buffer.buffer);
    SCFree(hdrnames);
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

HttpHeaderBuffer *HttpHeaderGetBufferSpace(DetectEngineThreadCtx *det_ctx, Flow *f, uint8_t flags,
        const int keyword_id, HttpHeaderThreadData **ret_hdr_td)
{
    *ret_hdr_td = NULL;

    HttpHeaderThreadData *hdr_td =
        DetectThreadCtxGetGlobalKeywordThreadCtx(det_ctx, keyword_id);
    if (hdr_td == NULL)
        return NULL;
    *ret_hdr_td = hdr_td;

    HttpHeaderBuffer *buf = &hdr_td->buffer;
    buf->len = 0;
    return buf;
}
