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
 * Implements support http_protocol sticky buffer
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
#include "detect-http-protocol.h"

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

#define KEYWORD_NAME "http_protocol"
#define KEYWORD_DOC "http-keywords.html#http-protocol"
#define BUFFER_NAME "http_protocol"
#define BUFFER_DESC "http protocol"
static int g_buffer_id = 0;

/** \brief HTTP Protocol Mpm prefilter callback
 *
 *  \param det_ctx detection engine thread ctx
 *  \param p packet to inspect
 *  \param f flow to inspect
 *  \param txv tx to inspect
 *  \param pectx inspection context
 */
static void PrefilterTxHttpRequestProtocol(DetectEngineThreadCtx *det_ctx,
        const void *pectx,
        Packet *p, Flow *f, void *txv,
        const uint64_t idx, const uint8_t flags)
{
    SCEnter();

    const MpmCtx *mpm_ctx = (MpmCtx *)pectx;
    htp_tx_t *tx = (htp_tx_t *)txv;

    if (tx->request_protocol == NULL)
        return;

    uint32_t buffer_len = bstr_size(tx->request_protocol);
    const uint8_t *buffer = bstr_ptr(tx->request_protocol);

    if (buffer_len >= mpm_ctx->minlen) {
        (void)mpm_table[mpm_ctx->mpm_type].Search(mpm_ctx,
                &det_ctx->mtcu, &det_ctx->pmq, buffer, buffer_len);
    }
}

static int PrefilterTxHttpRequestProtocolRegister(SigGroupHead *sgh, MpmCtx *mpm_ctx)
{
    SCEnter();

    int r = PrefilterAppendTxEngine(sgh, PrefilterTxHttpRequestProtocol,
        ALPROTO_HTTP, HTP_REQUEST_LINE,
        mpm_ctx, NULL, KEYWORD_NAME " (request)");
    return r;
}

/** \brief HTTP Protocol Mpm prefilter callback
 *
 *  \param det_ctx detection engine thread ctx
 *  \param p packet to inspect
 *  \param f flow to inspect
 *  \param txv tx to inspect
 *  \param pectx inspection context
 */
static void PrefilterTxHttpResponseProtocol(DetectEngineThreadCtx *det_ctx,
        const void *pectx,
        Packet *p, Flow *f, void *txv,
        const uint64_t idx, const uint8_t flags)
{
    SCEnter();

    const MpmCtx *mpm_ctx = (MpmCtx *)pectx;
    htp_tx_t *tx = (htp_tx_t *)txv;

    if (tx->response_protocol == NULL)
        return;

    uint32_t buffer_len = bstr_size(tx->response_protocol);
    const uint8_t *buffer = bstr_ptr(tx->response_protocol);

    if (buffer_len >= mpm_ctx->minlen) {
        (void)mpm_table[mpm_ctx->mpm_type].Search(mpm_ctx,
                &det_ctx->mtcu, &det_ctx->pmq, buffer, buffer_len);
    }
}

static int PrefilterTxHttpResponseProtocolRegister(SigGroupHead *sgh, MpmCtx *mpm_ctx)
{
    SCEnter();

    int r = PrefilterAppendTxEngine(sgh, PrefilterTxHttpResponseProtocol,
        ALPROTO_HTTP, HTP_RESPONSE_LINE,
        mpm_ctx, NULL, KEYWORD_NAME " (response)");
    return r;
}

static int InspectEngineHttpProtocol(ThreadVars *tv,
        DetectEngineCtx *de_ctx, DetectEngineThreadCtx *det_ctx,
        const Signature *s, const SigMatchData *smd,
        Flow *f, uint8_t flags, void *alstate, void *tx, uint64_t tx_id)
{
    bstr *str = NULL;
    htp_tx_t *http_tx = tx;

    if (flags & STREAM_TOSERVER)
        str = http_tx->request_protocol;
    else if (flags & STREAM_TOCLIENT)
        str = http_tx->response_protocol;

    if (str == NULL)
        goto end;

    uint32_t buffer_len = bstr_size(str);
    uint8_t *buffer = bstr_ptr(str);
    if (buffer == NULL ||buffer_len == 0)
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
        if (AppLayerParserGetStateProgress(IPPROTO_TCP, ALPROTO_HTTP, tx, flags) > HTP_REQUEST_LINE)
            return DETECT_ENGINE_INSPECT_SIG_CANT_MATCH;
    } else {
        if (AppLayerParserGetStateProgress(IPPROTO_TCP, ALPROTO_HTTP, tx, flags) > HTP_RESPONSE_LINE)
            return DETECT_ENGINE_INSPECT_SIG_CANT_MATCH;
    }
    return DETECT_ENGINE_INSPECT_SIG_NO_MATCH;
}

static int DetectHttpProtocolSetup(DetectEngineCtx *de_ctx, Signature *s, const char *arg)
{
    s->init_data->list = g_buffer_id;
    return 0;
}

static void DetectHttpProtocolSetupCallback(Signature *s)
{
    SCLogDebug("callback invoked by %u", s->id);
    s->mask |= SIG_MASK_REQUIRE_HTTP_STATE;
}

/**
 * \brief Registers the keyword handlers for the "http_header" keyword.
 */
void DetectHttpProtocolRegister(void)
{
    sigmatch_table[DETECT_AL_HTTP_PROTOCOL].name = KEYWORD_NAME;
    sigmatch_table[DETECT_AL_HTTP_PROTOCOL].desc = BUFFER_NAME " sticky buffer";
    sigmatch_table[DETECT_AL_HTTP_PROTOCOL].url = DOC_URL DOC_VERSION "/rules/" KEYWORD_DOC;
    sigmatch_table[DETECT_AL_HTTP_PROTOCOL].Setup = DetectHttpProtocolSetup;

    sigmatch_table[DETECT_AL_HTTP_PROTOCOL].flags |= SIGMATCH_NOOPT ;

    DetectAppLayerMpmRegister(BUFFER_NAME, SIG_FLAG_TOSERVER, 2,
            PrefilterTxHttpRequestProtocolRegister);
    DetectAppLayerMpmRegister(BUFFER_NAME, SIG_FLAG_TOCLIENT, 2,
            PrefilterTxHttpResponseProtocolRegister);

    DetectAppLayerInspectEngineRegister(BUFFER_NAME,
            ALPROTO_HTTP, SIG_FLAG_TOSERVER, HTP_REQUEST_LINE,
            InspectEngineHttpProtocol);
    DetectAppLayerInspectEngineRegister(BUFFER_NAME,
            ALPROTO_HTTP, SIG_FLAG_TOCLIENT, HTP_RESPONSE_LINE,
            InspectEngineHttpProtocol);

    DetectBufferTypeSetDescriptionByName(BUFFER_NAME,
            BUFFER_DESC);

    DetectBufferTypeRegisterSetupCallback(BUFFER_NAME,
            DetectHttpProtocolSetupCallback);

    g_buffer_id = DetectBufferTypeGetByName(BUFFER_NAME);
}
