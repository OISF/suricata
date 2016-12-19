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


/**
 * \file
 *
 * \author Victor Julien <victor@inliniac.net>
 *
 * Implements support http_header_names
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

#define KEYWORD_NAME "http_header_names"
#define KEYWORD_DOC "http-keywords#http-header-names"
#define BUFFER_NAME "http_header_names"
#define BUFFER_DESC "http header names"
static int g_buffer_id = 0;
static int g_keyword_thread_id = 0;

#define BUFFER_TX_STEP      4
#define BUFFER_SIZE_STEP    256

typedef struct Buffer_ {
    uint8_t *buffer;
    uint32_t size;      /**< buffer size */
    uint32_t len;       /**< part of buffer in use */
} Buffer;

typedef struct HttpHeaderNamesThreadData_ {
    Buffer *buffers;        /**< array of buffers */
    uint16_t buffers_size;  /**< number of buffers */
    uint16_t buffers_list_len;
    uint64_t start_tx_id;
    uint64_t tick;
} HttpHeaderNamesThreadData;

static inline int CreateSpace(HttpHeaderNamesThreadData *hn, uint64_t size);
static inline int ExpandBuffer(Buffer *buf, uint32_t size);

static void *HttpHeaderNamesThreadDataInit(void *data)
{
    HttpHeaderNamesThreadData *d = SCCalloc(1, sizeof(*d));
    if (d != NULL) {
        /* initialize minimal buffers */
        (void)CreateSpace(d, 1);
        int i;
        for (i = 0; i < d->buffers_size; i++) {
            (void)ExpandBuffer(&d->buffers[i], 1);
        }
    }
    return d;
}

static void HttpHeaderNamesThreadDataFree(void *data)
{
    HttpHeaderNamesThreadData *hdrnames = data;

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

static void Reset(HttpHeaderNamesThreadData *hdrnames, uint64_t tick)
{
    uint16_t i;
    for (i = 0; i < hdrnames->buffers_list_len; i++) {
        hdrnames->buffers[i].len = 0;
    }
    hdrnames->buffers_list_len = 0;
    hdrnames->start_tx_id = 0;
    hdrnames->tick = tick;
}

static inline int CreateSpace(HttpHeaderNamesThreadData *hn, uint64_t size)
{
    if (size >= SHRT_MAX)
        return -1;

    if (size > hn->buffers_size) {
        uint16_t extra = BUFFER_TX_STEP;
        while (hn->buffers_size + extra < size) {
            extra += BUFFER_TX_STEP;
        }
        SCLogDebug("adding %u to the buffer", (uint)extra);

        void *ptmp = SCRealloc(hn->buffers,
                         (hn->buffers_size + extra) * sizeof(Buffer));
        if (ptmp == NULL) {
            SCFree(hn->buffers);
            hn->buffers = NULL;
            hn->buffers_size = 0;
            hn->buffers_list_len = 0;
            return -1;
        }
        hn->buffers = ptmp;
        memset(hn->buffers + hn->buffers_size, 0, extra * sizeof(Buffer));
        hn->buffers_size += extra;
    }

    return 0;
}

static inline int ExpandBuffer(Buffer *buf, uint32_t size)
{
    size_t extra = BUFFER_SIZE_STEP;
    while ((buf->size + extra) < (size + buf->len)) {
        extra += BUFFER_SIZE_STEP;
    }
    SCLogDebug("adding %u to the buffer", (uint)extra);

    uint8_t *new_buffer = SCRealloc(buf->buffer, buf->size + extra);
    if (unlikely(new_buffer == NULL)) {
        buf->len = 0;
        return -1;
    }
    buf->buffer = new_buffer;
    buf->size += extra;
    return 0;
}

static Buffer *GetBufferSpaceForTXID(DetectEngineThreadCtx *det_ctx,
        Flow *f, uint8_t flags, uint64_t tx_id)
{
    int index = 0;

    HttpHeaderNamesThreadData *hdrnames =
        DetectThreadCtxGetGlobalKeywordThreadCtx(det_ctx, g_keyword_thread_id);
    if (hdrnames == NULL)
        return NULL;
    if (hdrnames->tick != det_ctx->ticker)
        Reset(hdrnames, det_ctx->ticker);

    if (hdrnames->buffers_list_len == 0) {
        /* get the inspect id to use as a 'base id' */
        uint64_t base_inspect_id = AppLayerParserGetTransactionInspectId(f->alparser, flags);
        BUG_ON(base_inspect_id > tx_id);
        /* see how many space we need for the current tx_id */
        uint64_t txs = (tx_id - base_inspect_id) + 1;
        if (CreateSpace(hdrnames, txs) < 0)
            return NULL;

        index = (tx_id - base_inspect_id);
        hdrnames->start_tx_id = base_inspect_id;
        hdrnames->buffers_list_len = txs;
    } else {
        /* tx fits in our current buffers */
        if ((tx_id - hdrnames->start_tx_id) < hdrnames->buffers_list_len) {
            /* if we previously reassembled, return that buffer */
            if (hdrnames->buffers[(tx_id - hdrnames->start_tx_id)].len != 0) {
                return &hdrnames->buffers[(tx_id - hdrnames->start_tx_id)];
            }
            /* otherwise fall through */
        } else {
            /* not enough space, lets expand */
            uint64_t txs = (tx_id - hdrnames->start_tx_id) + 1;
            if (CreateSpace(hdrnames, txs) < 0)
                return NULL;

            hdrnames->buffers_list_len = txs;
        }
        index = (tx_id - hdrnames->start_tx_id);
    }
    Buffer *buf = &hdrnames->buffers[index];
    return buf;
}

static uint8_t *GetBufferForTX(htp_tx_t *tx, uint64_t tx_id,
        DetectEngineCtx *de_ctx, DetectEngineThreadCtx *det_ctx,
        Flow *f, HtpState *htp_state, uint8_t flags,
        uint32_t *buffer_len)
{
    *buffer_len = 0;

    Buffer *buf = GetBufferSpaceForTXID(det_ctx, f, flags, tx_id);
    if (unlikely(buf == NULL)) {
        return NULL;
    } else if (buf->len > 0) {
        /* already filled buf, reuse */
        *buffer_len = buf->len;
        return buf->buffer;
    }

    htp_table_t *headers;
    if (flags & STREAM_TOSERVER) {
        if (AppLayerParserGetStateProgress(IPPROTO_TCP, ALPROTO_HTTP, tx, flags) <=
                HTP_REQUEST_HEADERS)
            return NULL;
        headers = tx->request_headers;
    } else {
        if (AppLayerParserGetStateProgress(IPPROTO_TCP, ALPROTO_HTTP, tx, flags) <=
                HTP_RESPONSE_HEADERS)
            return NULL;
        headers = tx->response_headers;
    }
    if (headers == NULL)
        return NULL;

    /* fill the buffer. \r\nName1\r\nName2\r\n\r\n */
    size_t i = 0;
    size_t no_of_headers = htp_table_size(headers);
    for (; i < no_of_headers; i++) {
        htp_header_t *h = htp_table_get_index(headers, i, NULL);
        size_t size = bstr_size(h->name) + 2; // for \r\n
        if (i == 0)
            size += 2;
        if (i + 1 == no_of_headers)
            size += 2;

        SCLogDebug("size %u + buf->len %u vs buf->size %u", (uint)size, buf->len, buf->size);
        if (size + buf->len > buf->size) {
            if (ExpandBuffer(buf, size) != 0) {
                return NULL;
            }
        }

        /* start with a \r\n */
        if (i == 0) {
            buf->buffer[buf->len++] = '\r';
            buf->buffer[buf->len++] = '\n';
        }

        memcpy(buf->buffer + buf->len, bstr_ptr(h->name), bstr_size(h->name));
        buf->len += bstr_size(h->name);
        buf->buffer[buf->len++] = '\r';
        buf->buffer[buf->len++] = '\n';

        /* end with an extra \r\n */
        if (i + 1 == no_of_headers) {
            buf->buffer[buf->len++] = '\r';
            buf->buffer[buf->len++] = '\n';
        }
    }

    *buffer_len = buf->len;
    return buf->buffer;
}

/** \brief HTTP Headers Mpm prefilter callback
 *
 *  \param det_ctx detection engine thread ctx
 *  \param p packet to inspect
 *  \param f flow to inspect
 *  \param txv tx to inspect
 *  \param pectx inspection context
 */
static void PrefilterTxHttpRequestHeaderNames(DetectEngineThreadCtx *det_ctx,
        const void *pectx,
        Packet *p, Flow *f, void *txv,
        const uint64_t idx, const uint8_t flags)
{
    SCEnter();

    const MpmCtx *mpm_ctx = (MpmCtx *)pectx;
    htp_tx_t *tx = (htp_tx_t *)txv;

    if (tx->request_headers == NULL)
        return;

    HtpState *htp_state = f->alstate;
    uint32_t buffer_len = 0;
    const uint8_t *buffer = GetBufferForTX(tx, idx,
            NULL, det_ctx, f, htp_state,
            flags, &buffer_len);

    if (buffer_len >= mpm_ctx->minlen) {
        (void)mpm_table[mpm_ctx->mpm_type].Search(mpm_ctx,
                &det_ctx->mtcu, &det_ctx->pmq, buffer, buffer_len);
    }
}
#if 0
static void PrefilterTxHttpRequestTrailers(DetectEngineThreadCtx *det_ctx,
        const void *pectx,
        Packet *p, Flow *f, void *txv,
        const uint64_t idx, const uint8_t flags)
{
    SCEnter();

    const MpmCtx *mpm_ctx = (MpmCtx *)pectx;
    htp_tx_t *tx = (htp_tx_t *)txv;

    if (tx->request_headers == NULL)
        return;
    const HtpTxUserData *htud = (const HtpTxUserData *)htp_tx_get_user_data(tx);
    /* if the request wasn't flagged as having a trailer, we skip */
    if (htud && !htud->request_has_trailers)
        return;

    HtpState *htp_state = f->alstate;
    uint32_t buffer_len = 0;
    const uint8_t *buffer = DetectEngineHHDGetBufferForTX(tx, idx,
                                                    NULL, det_ctx,
                                                    f, htp_state,
                                                    flags,
                                                    &buffer_len);

    if (buffer_len >= mpm_ctx->minlen) {
        (void)mpm_table[mpm_ctx->mpm_type].Search(mpm_ctx,
                &det_ctx->mtcu, &det_ctx->pmq, buffer, buffer_len);
    }
}
#endif
int PrefilterTxHttpRequestHeaderNamesRegister(SigGroupHead *sgh, MpmCtx *mpm_ctx)
{
    SCEnter();

    int r = PrefilterAppendTxEngine(sgh, PrefilterTxHttpRequestHeaderNames,
        ALPROTO_HTTP, HTP_REQUEST_HEADERS,
        mpm_ctx, NULL, KEYWORD_NAME " (request)");
    return r;
#if 0
    if (r != 0)
        return r;
    return PrefilterAppendTxEngine(sgh, PrefilterTxHttpRequestTrailers,
        ALPROTO_HTTP, HTP_REQUEST_TRAILER,
        mpm_ctx, NULL, "http_header (request)");
#endif
}

/** \brief HTTP Headers Mpm prefilter callback
 *
 *  \param det_ctx detection engine thread ctx
 *  \param p packet to inspect
 *  \param f flow to inspect
 *  \param txv tx to inspect
 *  \param pectx inspection context
 */
static void PrefilterTxHttpResponseHeaderNames(DetectEngineThreadCtx *det_ctx,
        const void *pectx,
        Packet *p, Flow *f, void *txv,
        const uint64_t idx, const uint8_t flags)
{
    SCEnter();

    const MpmCtx *mpm_ctx = (MpmCtx *)pectx;
    htp_tx_t *tx = (htp_tx_t *)txv;

    if (tx->response_headers == NULL)
        return;

    HtpState *htp_state = f->alstate;
    uint32_t buffer_len = 0;
    const uint8_t *buffer = GetBufferForTX(tx, idx, NULL, det_ctx,
            f, htp_state, flags, &buffer_len);

    if (buffer_len >= mpm_ctx->minlen) {
        (void)mpm_table[mpm_ctx->mpm_type].Search(mpm_ctx,
                &det_ctx->mtcu, &det_ctx->pmq, buffer, buffer_len);
    }
}
#if 0
static void PrefilterTxHttpResponseTrailers(DetectEngineThreadCtx *det_ctx,
        const void *pectx,
        Packet *p, Flow *f, void *txv,
        const uint64_t idx, const uint8_t flags)
{
    SCEnter();

    const MpmCtx *mpm_ctx = (MpmCtx *)pectx;
    htp_tx_t *tx = (htp_tx_t *)txv;

    if (tx->response_headers == NULL)
        return;
    const HtpTxUserData *htud = (const HtpTxUserData *)htp_tx_get_user_data(tx);
    /* if the request wasn't flagged as having a trailer, we skip */
    if (htud && !htud->response_has_trailers)
        return;

    HtpState *htp_state = f->alstate;
    uint32_t buffer_len = 0;
    const uint8_t *buffer = DetectEngineHHDGetBufferForTX(tx, idx,
                                                    NULL, det_ctx,
                                                    f, htp_state,
                                                    flags,
                                                    &buffer_len);

    if (buffer_len >= mpm_ctx->minlen) {
        (void)mpm_table[mpm_ctx->mpm_type].Search(mpm_ctx,
                &det_ctx->mtcu, &det_ctx->pmq, buffer, buffer_len);
    }
}
#endif
int PrefilterTxHttpResponseHeaderNamesRegister(SigGroupHead *sgh, MpmCtx *mpm_ctx)
{
    SCEnter();

    int r = PrefilterAppendTxEngine(sgh, PrefilterTxHttpResponseHeaderNames,
        ALPROTO_HTTP, HTP_RESPONSE_HEADERS,
        mpm_ctx, NULL, KEYWORD_NAME " (response)");
    return r;
#if 0
    if (r != 0)
        return r;
    return PrefilterAppendTxEngine(sgh, PrefilterTxHttpResponseTrailers,
        ALPROTO_HTTP, HTP_RESPONSE_TRAILER,
        mpm_ctx, NULL, "http_header (response)");
#endif
}

int InspectEngineHttpHeaderNames(ThreadVars *tv,
        DetectEngineCtx *de_ctx, DetectEngineThreadCtx *det_ctx,
        const Signature *s, const SigMatchData *smd,
        Flow *f, uint8_t flags, void *alstate, void *tx, uint64_t tx_id)
{
    HtpState *htp_state = (HtpState *)alstate;
    uint32_t buffer_len = 0;
    uint8_t *buffer = GetBufferForTX(tx, tx_id,
            de_ctx, det_ctx, f, htp_state,
            flags, &buffer_len);
    if (buffer_len == 0)
        goto end;

    det_ctx->buffer_offset = 0;
    det_ctx->discontinue_matching = 0;
    det_ctx->inspection_recursion_counter = 0;
    int r = DetectEngineContentInspection(de_ctx, det_ctx, s, smd,
                                          f,
                                          buffer, buffer_len,
                                          0,
                                          DETECT_ENGINE_CONTENT_INSPECTION_MODE_STATE, NULL);
    if (r == 1)
        return DETECT_ENGINE_INSPECT_SIG_MATCH;

 end:
    if (flags & STREAM_TOSERVER) {
        if (AppLayerParserGetStateProgress(IPPROTO_TCP, ALPROTO_HTTP, tx, flags) > HTP_REQUEST_HEADERS)
            return DETECT_ENGINE_INSPECT_SIG_CANT_MATCH;
    } else {
        if (AppLayerParserGetStateProgress(IPPROTO_TCP, ALPROTO_HTTP, tx, flags) > HTP_RESPONSE_HEADERS)
            return DETECT_ENGINE_INSPECT_SIG_CANT_MATCH;
    }
    return DETECT_ENGINE_INSPECT_SIG_NO_MATCH;
}

/**
 * \brief The setup function for the http_header keyword for a signature.
 *
 * \param de_ctx Pointer to the detection engine context.
 * \param s      Pointer to signature for the current Signature being parsed
 *               from the rules.
 * \param m      Pointer to the head of the SigMatchs for the current rule
 *               being parsed.
 * \param arg    Pointer to the string holding the keyword value.
 *
 * \retval  0 On success.
 * \retval -1 On failure.
 */
int DetectHttpHeaderNamesSetup(DetectEngineCtx *de_ctx, Signature *s, char *arg)
{
    s->init_data->list = g_buffer_id;
    return 0;
}

static void DetectHttpHeaderNamesSetupCallback(Signature *s)
{
    SCLogDebug("callback invoked by %u", s->id);
    s->mask |= SIG_MASK_REQUIRE_HTTP_STATE;
}

/**
 * \brief Registers the keyword handlers for the "http_header" keyword.
 */
void DetectHttpHeaderNamesRegister(void)
{
    sigmatch_table[DETECT_AL_HTTP_HEADER_NAMES].name = KEYWORD_NAME;
    sigmatch_table[DETECT_AL_HTTP_HEADER_NAMES].desc = BUFFER_NAME " sticky buffer";
    sigmatch_table[DETECT_AL_HTTP_HEADER_NAMES].url = DOC_URL DOC_VERSION "/rules/" KEYWORD_DOC;
    sigmatch_table[DETECT_AL_HTTP_HEADER_NAMES].Setup = DetectHttpHeaderNamesSetup;

    sigmatch_table[DETECT_AL_HTTP_HEADER_NAMES].flags |= SIGMATCH_NOOPT ;
    sigmatch_table[DETECT_AL_HTTP_HEADER_NAMES].flags |= SIGMATCH_PAYLOAD ;

    DetectAppLayerMpmRegister(BUFFER_NAME, SIG_FLAG_TOSERVER, 2,
            PrefilterTxHttpRequestHeaderNamesRegister);
    DetectAppLayerMpmRegister(BUFFER_NAME, SIG_FLAG_TOCLIENT, 2,
            PrefilterTxHttpResponseHeaderNamesRegister);

    DetectAppLayerInspectEngineRegister(BUFFER_NAME,
            ALPROTO_HTTP, SIG_FLAG_TOSERVER,
            InspectEngineHttpHeaderNames);
    DetectAppLayerInspectEngineRegister(BUFFER_NAME,
            ALPROTO_HTTP, SIG_FLAG_TOCLIENT,
            InspectEngineHttpHeaderNames);

    DetectBufferTypeSetDescriptionByName(BUFFER_NAME,
            BUFFER_DESC);

    DetectBufferTypeRegisterSetupCallback(BUFFER_NAME,
            DetectHttpHeaderNamesSetupCallback);

    g_buffer_id = DetectBufferTypeGetByName(BUFFER_NAME);

    g_keyword_thread_id = DetectRegisterThreadCtxGlobalFuncs(KEYWORD_NAME,
            HttpHeaderNamesThreadDataInit, HttpHeaderNamesThreadDataFree);

    SCLogDebug("keyword %s registered. Thread id %d. "
            "Buffer %s registered. Buffer id %d",
            KEYWORD_NAME, g_keyword_thread_id,
            BUFFER_NAME, g_buffer_id);
}

