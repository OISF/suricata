/* Copyright (C) 2007-2019 Open Information Security Foundation
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
 * Implements http_start
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
#include "detect-http-header-common.h"
#include "detect-http-start.h"

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

#define KEYWORD_NAME "http.start"
#define KEYWORD_NAME_LEGACY "http_start"
#define KEYWORD_DOC "http-keywords.html#http-start"
#define BUFFER_NAME "http_start"
#define BUFFER_DESC "http start: request/response line + headers"
static int g_buffer_id = 0;
static int g_keyword_thread_id = 0;

#define BUFFER_TX_STEP      4
#define BUFFER_SIZE_STEP    2048
static HttpHeaderThreadDataConfig g_td_config = { BUFFER_TX_STEP, BUFFER_SIZE_STEP };

static uint8_t *GetBufferForTX(htp_tx_t *tx, uint64_t tx_id,
        DetectEngineThreadCtx *det_ctx,
        Flow *f, uint8_t flags, uint32_t *buffer_len)
{
    *buffer_len = 0;

    HttpHeaderThreadData *hdr_td = NULL;
    HttpHeaderBuffer *buf = HttpHeaderGetBufferSpaceForTXID(det_ctx, f, flags,
            tx_id, g_keyword_thread_id, &hdr_td);
    if (unlikely(buf == NULL)) {
        return NULL;
    } else if (buf->len > 0) {
        /* already filled buf, reuse */
        *buffer_len = buf->len;
        return buf->buffer;
    }

    bstr *line = NULL;
    htp_table_t *headers;
    if (flags & STREAM_TOSERVER) {
        if (AppLayerParserGetStateProgress(IPPROTO_TCP, ALPROTO_HTTP, tx, flags) <=
                HTP_REQUEST_HEADERS)
            return NULL;
        line = tx->request_line;
        headers = tx->request_headers;
    } else {
        if (AppLayerParserGetStateProgress(IPPROTO_TCP, ALPROTO_HTTP, tx, flags) <=
                HTP_RESPONSE_HEADERS)
            return NULL;
        headers = tx->response_headers;
        line = tx->response_line;
    }
    if (line == NULL || headers == NULL)
        return NULL;

    size_t line_size = bstr_len(line) + 2;
    if (line_size + buf->len > buf->size) {
        if (HttpHeaderExpandBuffer(hdr_td, buf, line_size) != 0) {
            return NULL;
        }
    }
    memcpy(buf->buffer + buf->len, bstr_ptr(line), bstr_size(line));
    buf->len += bstr_size(line);
    buf->buffer[buf->len++] = '\r';
    buf->buffer[buf->len++] = '\n';

    size_t i = 0;
    size_t no_of_headers = htp_table_size(headers);
    for (; i < no_of_headers; i++) {
        htp_header_t *h = htp_table_get_index(headers, i, NULL);
        size_t size1 = bstr_size(h->name);
        size_t size2 = bstr_size(h->value);
        size_t size = size1 + size2 + 4;
        if (i + 1 == no_of_headers)
            size += 2;
        if (size + buf->len > buf->size) {
            if (HttpHeaderExpandBuffer(hdr_td, buf, size) != 0) {
                return NULL;
            }
        }

        memcpy(buf->buffer + buf->len, bstr_ptr(h->name), bstr_size(h->name));
        buf->len += bstr_size(h->name);
        buf->buffer[buf->len++] = ':';
        buf->buffer[buf->len++] = ' ';
        memcpy(buf->buffer + buf->len, bstr_ptr(h->value), bstr_size(h->value));
        buf->len += bstr_size(h->value);
        buf->buffer[buf->len++] = '\r';
        buf->buffer[buf->len++] = '\n';
        if (i + 1 == no_of_headers) {
            buf->buffer[buf->len++] = '\r';
            buf->buffer[buf->len++] = '\n';
        }
    }

    *buffer_len = buf->len;
    return buf->buffer;
}

typedef struct PrefilterMpmHttpStartCtx {
    int list_id;
    const MpmCtx *mpm_ctx;
    const DetectEngineTransforms *transforms;
} PrefilterMpmHttpStartCtx;

/** \brief HTTP Headers Mpm prefilter callback
 *
 *  \param det_ctx detection engine thread ctx
 *  \param p packet to inspect
 *  \param f flow to inspect
 *  \param txv tx to inspect
 *  \param pectx inspection context
 */
static void PrefilterTxHttpRequestStart(DetectEngineThreadCtx *det_ctx,
        const void *pectx,
        Packet *p, Flow *f, void *txv,
        const uint64_t idx, const uint8_t flags)
{
    SCEnter();

    const PrefilterMpmHttpStartCtx *ctx = pectx;
    const MpmCtx *mpm_ctx = ctx->mpm_ctx;
    SCLogDebug("running on list %d", ctx->list_id);

    const int list_id = ctx->list_id;
    InspectionBuffer *buffer = InspectionBufferGet(det_ctx, list_id);
    if (buffer->inspect == NULL) {
        uint32_t rawdata_len = 0;
        uint8_t *rawdata = GetBufferForTX(txv, idx, det_ctx,
                f, flags, &rawdata_len);
        if (rawdata_len == 0)
            return;

        /* setup buffer and apply transforms */
        InspectionBufferSetup(buffer, rawdata, rawdata_len);
        InspectionBufferApplyTransforms(buffer, ctx->transforms);
    }

    const uint32_t data_len = buffer->inspect_len;
    const uint8_t *data = buffer->inspect;

    SCLogDebug("mpm'ing buffer:");
    //PrintRawDataFp(stdout, data, data_len);

    if (data != NULL && data_len >= mpm_ctx->minlen) {
        (void)mpm_table[mpm_ctx->mpm_type].Search(mpm_ctx,
                &det_ctx->mtcu, &det_ctx->pmq, data, data_len);
    }
}

static void PrefilterMpmHttpHeaderFree(void *ptr)
{
    SCFree(ptr);
}

static int PrefilterTxHttpRequestStartRegister(DetectEngineCtx *de_ctx,
        SigGroupHead *sgh, MpmCtx *mpm_ctx,
        const DetectMpmAppLayerRegistery *mpm_reg, int list_id)
{
    SCEnter();

    PrefilterMpmHttpStartCtx *pectx = SCCalloc(1, sizeof(*pectx));
    if (pectx == NULL)
        return -1;
    pectx->list_id = list_id;
    pectx->mpm_ctx = mpm_ctx;
    pectx->transforms = &mpm_reg->v2.transforms;

    int r = PrefilterAppendTxEngine(de_ctx, sgh, PrefilterTxHttpRequestStart,
            mpm_reg->v2.alproto, HTP_REQUEST_HEADERS,
            pectx, PrefilterMpmHttpHeaderFree, mpm_reg->pname);
    if (r != 0) {
        SCFree(pectx);
        return r;
    }

    return r;
}

/** \brief HTTP Headers Mpm prefilter callback
 *
 *  \param det_ctx detection engine thread ctx
 *  \param p packet to inspect
 *  \param f flow to inspect
 *  \param txv tx to inspect
 *  \param pectx inspection context
 */
static void PrefilterTxHttpResponseStart(DetectEngineThreadCtx *det_ctx,
        const void *pectx,
        Packet *p, Flow *f, void *txv,
        const uint64_t idx, const uint8_t flags)
{
    SCEnter();

    const PrefilterMpmHttpStartCtx *ctx = pectx;
    const MpmCtx *mpm_ctx = ctx->mpm_ctx;
    SCLogDebug("running on list %d", ctx->list_id);

    const int list_id = ctx->list_id;
    InspectionBuffer *buffer = InspectionBufferGet(det_ctx, list_id);
    if (buffer->inspect == NULL) {
        uint32_t rawdata_len = 0;
        uint8_t *rawdata = GetBufferForTX(txv, idx, det_ctx,
                f, flags, &rawdata_len);
        if (rawdata_len == 0)
            return;

        /* setup buffer and apply transforms */
        InspectionBufferSetup(buffer, rawdata, rawdata_len);
        InspectionBufferApplyTransforms(buffer, ctx->transforms);
    }

    const uint32_t data_len = buffer->inspect_len;
    const uint8_t *data = buffer->inspect;

    SCLogDebug("mpm'ing buffer:");
    //PrintRawDataFp(stdout, data, data_len);

    if (data != NULL && data_len >= mpm_ctx->minlen) {
        (void)mpm_table[mpm_ctx->mpm_type].Search(mpm_ctx,
                &det_ctx->mtcu, &det_ctx->pmq, data, data_len);
    }
}

static int PrefilterTxHttpResponseStartRegister(DetectEngineCtx *de_ctx,
        SigGroupHead *sgh, MpmCtx *mpm_ctx,
        const DetectMpmAppLayerRegistery *mpm_reg, int list_id)
{
    SCEnter();

    PrefilterMpmHttpStartCtx *pectx = SCCalloc(1, sizeof(*pectx));
    if (pectx == NULL)
        return -1;
    pectx->list_id = list_id;
    pectx->mpm_ctx = mpm_ctx;
    pectx->transforms = &mpm_reg->v2.transforms;

    int r = PrefilterAppendTxEngine(de_ctx, sgh, PrefilterTxHttpResponseStart,
            mpm_reg->v2.alproto, HTP_RESPONSE_HEADERS,
            pectx, PrefilterMpmHttpHeaderFree, mpm_reg->pname);
    if (r != 0) {
        SCFree(pectx);
        return r;
    }

    return r;
}

static int InspectEngineHttpStart(
        DetectEngineCtx *de_ctx, DetectEngineThreadCtx *det_ctx,
        const DetectEngineAppInspectionEngine *engine,
        const Signature *s,
        Flow *f, uint8_t flags, void *alstate, void *txv, uint64_t tx_id)
{
    const int list_id = engine->sm_list;
    InspectionBuffer *buffer = InspectionBufferGet(det_ctx, list_id);
    if (buffer->inspect == NULL) {
        SCLogDebug("setting up inspect buffer %d", list_id);

        /* if prefilter didn't already run, we need to consider transformations */
        const DetectEngineTransforms *transforms = NULL;
        if (!engine->mpm) {
            transforms = engine->v2.transforms;
        }

        uint32_t rawdata_len = 0;
        uint8_t *rawdata = GetBufferForTX(txv, tx_id, det_ctx,
                f, flags, &rawdata_len);
        if (rawdata_len == 0) {
            SCLogDebug("no data");
            goto end;
        }
        /* setup buffer and apply transforms */
        InspectionBufferSetup(buffer, rawdata, rawdata_len);
        InspectionBufferApplyTransforms(buffer, transforms);
    }

    const uint32_t data_len = buffer->inspect_len;
    const uint8_t *data = buffer->inspect;
    const uint64_t offset = buffer->inspect_offset;

    det_ctx->buffer_offset = 0;
    det_ctx->discontinue_matching = 0;
    det_ctx->inspection_recursion_counter = 0;
    int r = DetectEngineContentInspection(de_ctx, det_ctx, s, engine->smd,
            NULL, f, (uint8_t *)data, data_len, offset,
            DETECT_CI_FLAGS_SINGLE,
            DETECT_ENGINE_CONTENT_INSPECTION_MODE_STATE);
    if (r == 1)
        return DETECT_ENGINE_INSPECT_SIG_MATCH;

 end:
    if (flags & STREAM_TOSERVER) {
        if (AppLayerParserGetStateProgress(IPPROTO_TCP, ALPROTO_HTTP, txv, flags) > HTP_REQUEST_HEADERS)
            return DETECT_ENGINE_INSPECT_SIG_CANT_MATCH;
    } else {
        if (AppLayerParserGetStateProgress(IPPROTO_TCP, ALPROTO_HTTP, txv, flags) > HTP_RESPONSE_HEADERS)
            return DETECT_ENGINE_INSPECT_SIG_CANT_MATCH;
    }
    return DETECT_ENGINE_INSPECT_SIG_NO_MATCH;
}

static int DetectHttpStartSetup(DetectEngineCtx *de_ctx, Signature *s, const char *arg)
{
    if (DetectBufferSetActiveList(s, g_buffer_id) < 0)
        return -1;

    if (DetectSignatureSetAppProto(s, ALPROTO_HTTP) < 0)
        return -1;

    return 0;
}

/**
 * \brief Registers the keyword handlers for the "http_header" keyword.
 */
void DetectHttpStartRegister(void)
{
    sigmatch_table[DETECT_AL_HTTP_START].name = KEYWORD_NAME;
    sigmatch_table[DETECT_AL_HTTP_START].alias = KEYWORD_NAME_LEGACY;
    sigmatch_table[DETECT_AL_HTTP_START].desc = BUFFER_NAME " sticky buffer";
    sigmatch_table[DETECT_AL_HTTP_START].url = DOC_URL DOC_VERSION "/rules/" KEYWORD_DOC;
    sigmatch_table[DETECT_AL_HTTP_START].Setup = DetectHttpStartSetup;
    sigmatch_table[DETECT_AL_HTTP_START].flags |= SIGMATCH_NOOPT|SIGMATCH_INFO_STICKY_BUFFER;

    DetectAppLayerMpmRegister2(BUFFER_NAME, SIG_FLAG_TOSERVER, 2,
            PrefilterTxHttpRequestStartRegister, NULL, ALPROTO_HTTP,
            HTP_REQUEST_HEADERS);
    DetectAppLayerMpmRegister2(BUFFER_NAME, SIG_FLAG_TOCLIENT, 2,
            PrefilterTxHttpResponseStartRegister, NULL, ALPROTO_HTTP,
            HTP_RESPONSE_HEADERS);

    DetectAppLayerInspectEngineRegister2(BUFFER_NAME,
            ALPROTO_HTTP, SIG_FLAG_TOSERVER, HTP_REQUEST_HEADERS,
            InspectEngineHttpStart, NULL);
    DetectAppLayerInspectEngineRegister2(BUFFER_NAME,
            ALPROTO_HTTP, SIG_FLAG_TOCLIENT, HTP_RESPONSE_HEADERS,
            InspectEngineHttpStart, NULL);

    DetectBufferTypeSetDescriptionByName(BUFFER_NAME,
            BUFFER_DESC);

    g_buffer_id = DetectBufferTypeGetByName(BUFFER_NAME);

    g_keyword_thread_id = DetectRegisterThreadCtxGlobalFuncs(KEYWORD_NAME,
            HttpHeaderThreadDataInit, &g_td_config, HttpHeaderThreadDataFree);

    SCLogDebug("keyword %s registered. Thread id %d. "
            "Buffer %s registered. Buffer id %d",
            KEYWORD_NAME, g_keyword_thread_id,
            BUFFER_NAME, g_buffer_id);
}
