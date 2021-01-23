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


/**
 * \file
 *
 * \author Anoop Saldanha <anoopsaldanha@gmail.com>
 *
 * Implements support for the http_client_body keyword
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

#include "app-layer.h"
#include "app-layer-parser.h"
#include "app-layer-htp.h"
#include "detect-http-client-body.h"
#include "stream-tcp.h"

static int DetectEngineInspectBufferHttpRequest(DetectEngineCtx *, DetectEngineThreadCtx *,
        const DetectEngineAppInspectionEngine *, const Signature *, Flow *, uint8_t, void *, void *,
        uint64_t);
static int DetectHttpClientBodySetup(DetectEngineCtx *, Signature *, const char *);
static int DetectHttpClientBodySetupSticky(DetectEngineCtx *de_ctx, Signature *s, const char *str);
#ifdef UNITTESTS
static void DetectHttpClientBodyRegisterTests(void);
#endif
static void DetectHttpClientBodySetupCallback(const DetectEngineCtx *de_ctx,
                                              Signature *s);
static int g_http_client_body_buffer_id = 0;

static InspectionBuffer *HttpClientBodyGetDataCallback(
        DetectEngineThreadCtx *det_ctx,
        const DetectEngineTransforms *transforms,
        Flow *f, const uint8_t flow_flags,
        void *txv, const int list_id);

/**
 * \brief Registers the keyword handlers for the "http_client_body" keyword.
 */
void DetectHttpClientBodyRegister(void)
{
    /* http_client_body content modifier */
    sigmatch_table[DETECT_AL_HTTP_CLIENT_BODY].name = "http_client_body";
    sigmatch_table[DETECT_AL_HTTP_CLIENT_BODY].desc = "content modifier to match only on HTTP request-body";
    sigmatch_table[DETECT_AL_HTTP_CLIENT_BODY].url = "/rules/http-keywords.html#http-client-body";
    sigmatch_table[DETECT_AL_HTTP_CLIENT_BODY].Setup = DetectHttpClientBodySetup;
#ifdef UNITTESTS
    sigmatch_table[DETECT_AL_HTTP_CLIENT_BODY].RegisterTests = DetectHttpClientBodyRegisterTests;
#endif
    sigmatch_table[DETECT_AL_HTTP_CLIENT_BODY].flags |= SIGMATCH_NOOPT ;
    sigmatch_table[DETECT_AL_HTTP_CLIENT_BODY].flags |= SIGMATCH_INFO_CONTENT_MODIFIER;
    sigmatch_table[DETECT_AL_HTTP_CLIENT_BODY].alternative = DETECT_HTTP_REQUEST_BODY;

    /* http.request_body sticky buffer */
    sigmatch_table[DETECT_HTTP_REQUEST_BODY].name = "http.request_body";
    sigmatch_table[DETECT_HTTP_REQUEST_BODY].desc = "sticky buffer to match the HTTP request body buffer";
    sigmatch_table[DETECT_HTTP_REQUEST_BODY].url = "/rules/http-keywords.html#http-client-body";
    sigmatch_table[DETECT_HTTP_REQUEST_BODY].Setup = DetectHttpClientBodySetupSticky;
    sigmatch_table[DETECT_HTTP_REQUEST_BODY].flags |= SIGMATCH_NOOPT;
    sigmatch_table[DETECT_HTTP_REQUEST_BODY].flags |= SIGMATCH_INFO_STICKY_BUFFER;

    DetectAppLayerInspectEngineRegister2("http_client_body", ALPROTO_HTTP1, SIG_FLAG_TOSERVER,
            HTP_REQUEST_BODY, DetectEngineInspectBufferHttpRequest, HttpClientBodyGetDataCallback);

    DetectAppLayerMpmRegister2("http_client_body", SIG_FLAG_TOSERVER, 2,
            PrefilterGenericMpmRegister, HttpClientBodyGetDataCallback, ALPROTO_HTTP1,
            HTP_REQUEST_BODY);

    DetectBufferTypeSetDescriptionByName("http_client_body",
            "http request body");

    DetectBufferTypeRegisterSetupCallback("http_client_body",
            DetectHttpClientBodySetupCallback);

    g_http_client_body_buffer_id = DetectBufferTypeGetByName("http_client_body");
}

static void DetectHttpClientBodySetupCallback(const DetectEngineCtx *de_ctx,
                                              Signature *s)
{
    SCLogDebug("callback invoked by %u", s->id);
    AppLayerHtpEnableRequestBodyCallback();

    /* client body needs to be inspected in sync with stream if possible */
    s->init_data->init_flags |= SIG_FLAG_INIT_NEED_FLUSH;
}

/**
 * \brief The setup function for the http_client_body keyword for a signature.
 *
 * \param de_ctx Pointer to the detection engine context.
 * \param s      Pointer to signature for the current Signature being parsed
 *               from the rules.
 * \param m      Pointer to the head of the SigMatchs for the current rule
 *               being parsed.
 * \param arg    Pointer to the string holding the keyword value.
 *
 * \retval  0 On success
 * \retval -1 On failure
 */
int DetectHttpClientBodySetup(DetectEngineCtx *de_ctx, Signature *s, const char *arg)
{
    return DetectEngineContentModifierBufferSetup(de_ctx, s, arg, DETECT_AL_HTTP_CLIENT_BODY,
            g_http_client_body_buffer_id, ALPROTO_HTTP1);
}

/**
 * \brief this function setup the http.request_body keyword used in the rule
 *
 * \param de_ctx   Pointer to the Detection Engine Context
 * \param s        Pointer to the Signature to which the current keyword belongs
 * \param str      Should hold an empty string always
 *
 * \retval 0       On success
 */
static int DetectHttpClientBodySetupSticky(DetectEngineCtx *de_ctx, Signature *s, const char *str)
{
    if (DetectBufferSetActiveList(s, g_http_client_body_buffer_id) < 0)
        return -1;
    if (DetectSignatureSetAppProto(s, ALPROTO_HTTP1) < 0)
        return -1;
    return 0;
}

static inline HtpBody *GetRequestBody(htp_tx_t *tx)
{
    HtpTxUserData *htud = (HtpTxUserData *)htp_tx_get_user_data(tx);
    if (htud == NULL) {
        SCLogDebug("no htud");
        return NULL;
    }

    return &htud->request_body;
}

static InspectionBuffer *HttpClientBodyGetDataCallback(DetectEngineThreadCtx *det_ctx,
        const DetectEngineTransforms *transforms,
        Flow *f, const uint8_t flow_flags,
        void *txv, const int list_id)
{
    SCEnter();

    InspectionBuffer *buffer = InspectionBufferGet(det_ctx, list_id);
    if (buffer->inspect != NULL)
        return buffer;

    htp_tx_t *tx = txv;
    HtpState *htp_state = f->alstate;
    const uint8_t flags = flow_flags;

    HtpBody *body = GetRequestBody(tx);
    if (body == NULL) {
        return NULL;
    }

    /* no new data */
    if (body->body_inspected == body->content_len_so_far) {
        SCLogDebug("[list id %d] no new data", list_id);
        return NULL;
    }

    HtpBodyChunk *cur = body->first;
    if (cur == NULL) {
        SCLogDebug("No http chunks to inspect for this transaction");
        return NULL;
    }

    SCLogDebug("[list_id %d] request.body_limit %u request_body.content_len_so_far %" PRIu64
               ", request.inspect_min_size %" PRIu32 ", EOF %s, progress > body? %s",
            list_id, htp_state->cfg->request.body_limit, body->content_len_so_far,
            htp_state->cfg->request.inspect_min_size, flags & STREAM_EOF ? "true" : "false",
            (AppLayerParserGetStateProgress(IPPROTO_TCP, ALPROTO_HTTP1, tx, flags) >
                    HTP_REQUEST_BODY)
                    ? "true"
                    : "false");

    if (!htp_state->cfg->http_body_inline) {
        /* inspect the body if the transfer is complete or we have hit
        * our body size limit */
        if ((htp_state->cfg->request.body_limit == 0 ||
                    body->content_len_so_far < htp_state->cfg->request.body_limit) &&
                body->content_len_so_far < htp_state->cfg->request.inspect_min_size &&
                !(AppLayerParserGetStateProgress(IPPROTO_TCP, ALPROTO_HTTP1, tx, flags) >
                        HTP_REQUEST_BODY) &&
                !(flags & STREAM_EOF)) {
            SCLogDebug("[list_id %d] we still haven't seen the entire request body.  "
                       "Let's defer body inspection till we see the "
                       "entire body.",
                    list_id);
            return NULL;
        }
    }

    /* get the inspect buffer
     *
     * make sure that we have at least the configured inspect_win size.
     * If we have more, take at least 1/4 of the inspect win size before
     * the new data.
     */
    uint64_t offset = 0;
    if (body->body_inspected > htp_state->cfg->request.inspect_min_size) {
        BUG_ON(body->content_len_so_far < body->body_inspected);
        uint64_t inspect_win = body->content_len_so_far - body->body_inspected;
        SCLogDebug("[list_id %d] inspect_win %" PRIu64, list_id, inspect_win);
        if (inspect_win < htp_state->cfg->request.inspect_window) {
            uint64_t inspect_short = htp_state->cfg->request.inspect_window - inspect_win;
            if (body->body_inspected < inspect_short)
                offset = 0;
            else
                offset = body->body_inspected - inspect_short;
        } else {
            offset = body->body_inspected - (htp_state->cfg->request.inspect_window / 4);
        }
    }

    const uint8_t *data;
    uint32_t data_len;

    StreamingBufferGetDataAtOffset(body->sb,
            &data, &data_len, offset);
    InspectionBufferSetup(det_ctx, list_id, buffer, data, data_len);
    InspectionBufferApplyTransforms(buffer, transforms);
    buffer->inspect_offset = offset;

    SCReturnPtr(buffer, "InspectionBuffer");
}

static int DetectEngineInspectBufferHttpRequest(DetectEngineCtx *de_ctx,
        DetectEngineThreadCtx *det_ctx, const DetectEngineAppInspectionEngine *engine,
        const Signature *s, Flow *f, uint8_t flags, void *alstate, void *txv, uint64_t tx_id)
{
    const int list_id = engine->sm_list;
    const InspectionBuffer *buffer = InspectionBufferGet(det_ctx, list_id);
    bool eof = false;
    SCLogDebug("[list_id %d]: signature: %s", list_id, s->sig_str);
    if (buffer->inspect == NULL) {
        SCLogDebug("running inspect on %d", list_id);

        eof = (AppLayerParserGetStateProgress(f->proto, f->alproto, txv, flags) > engine->progress);

        SCLogDebug("list %d mpm? %s transforms %p", engine->sm_list, engine->mpm ? "true" : "false",
                engine->v2.transforms);

        /* if prefilter didn't already run, we need to consider transformations */
        const DetectEngineTransforms *transforms = NULL;
        if (!engine->mpm) {
            transforms = engine->v2.transforms;
        }

        buffer = engine->v2.GetData(det_ctx, transforms, f, flags, txv, list_id);
        if (unlikely(buffer == NULL)) {
            return eof ? DETECT_ENGINE_INSPECT_SIG_CANT_MATCH : DETECT_ENGINE_INSPECT_SIG_NO_MATCH;
        }
    }

    const uint32_t data_len = buffer->inspect_len;
    const uint8_t *data = buffer->inspect;
    const uint64_t offset = buffer->inspect_offset;

    uint8_t ci_flags = eof ? DETECT_CI_FLAGS_END : 0;
    ci_flags |= (offset == 0 ? DETECT_CI_FLAGS_START : 0);
    ci_flags |= buffer->flags;

    det_ctx->discontinue_matching = 0;
    det_ctx->buffer_offset = 0;
    det_ctx->inspection_recursion_counter = 0;

    /* Inspect all the uricontents fetched on each
     * transaction at the app layer */
    int r = DetectEngineContentInspection(de_ctx, det_ctx, s, engine->smd, NULL, f, (uint8_t *)data,
            data_len, offset, ci_flags, DETECT_ENGINE_CONTENT_INSPECTION_MODE_STATE);

    /* Set to move inspected tracker to end of the data. HtpBodyPrune will consider
     * the window sizes when freeing data */

    HtpBody *body = GetRequestBody(txv);
    det_ctx->http_body_progress_updated = true;
    det_ctx->http_body_progress = body->content_len_so_far;

    if (r == 1) {
        return DETECT_ENGINE_INSPECT_SIG_MATCH;
    }

    if (AppLayerParserGetStateProgress(IPPROTO_TCP, ALPROTO_HTTP1, txv, flags) > HTP_REQUEST_BODY)
        return DETECT_ENGINE_INSPECT_SIG_CANT_MATCH;

    return DETECT_ENGINE_INSPECT_SIG_NO_MATCH;
}

#ifdef UNITTESTS
#include "tests/detect-http-client-body.c"
#endif /* UNITTESTS */

/**
 * @}
 */
