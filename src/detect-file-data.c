/* Copyright (C) 2007-2018 Open Information Security Foundation
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
 *
 */

#include "suricata-common.h"
#include "threads.h"
#include "debug.h"
#include "decode.h"

#include "detect.h"
#include "detect-parse.h"

#include "detect-engine.h"
#include "detect-engine-mpm.h"
#include "detect-engine-state.h"
#include "detect-engine-prefilter.h"
#include "detect-engine-content-inspection.h"
#include "detect-file-data.h"

#include "app-layer-parser.h"
#include "app-layer-htp.h"
#include "app-layer-smtp.h"

#include "flow.h"
#include "flow-var.h"
#include "flow-util.h"

#include "util-debug.h"
#include "util-spm-bm.h"
#include "util-unittest.h"
#include "util-unittest-helper.h"
#include "util-file-decompression.h"

static int DetectFiledataSetup (DetectEngineCtx *, Signature *, const char *);
#ifdef UNITTESTS
static void DetectFiledataRegisterTests(void);
#endif
static void DetectFiledataSetupCallback(const DetectEngineCtx *de_ctx,
                                        Signature *s);
static int g_file_data_buffer_id = 0;

/* HTTP */
static InspectionBuffer *HttpServerBodyGetDataCallback(DetectEngineThreadCtx *det_ctx,
        const DetectEngineTransforms *transforms,
        Flow *f, const uint8_t flow_flags,
        void *txv, const int list_id);

/* file API */
static int DetectEngineInspectFiledata(
        DetectEngineCtx *de_ctx, DetectEngineThreadCtx *det_ctx,
        const DetectEngineAppInspectionEngine *engine,
        const Signature *s,
        Flow *f, uint8_t flags, void *alstate, void *txv, uint64_t tx_id);
int PrefilterMpmFiledataRegister(DetectEngineCtx *de_ctx,
        SigGroupHead *sgh, MpmCtx *mpm_ctx,
        const DetectMpmAppLayerRegistery *mpm_reg, int list_id);

/**
 * \brief Registration function for keyword: file_data
 */
void DetectFiledataRegister(void)
{
    sigmatch_table[DETECT_FILE_DATA].name = "file.data";
    sigmatch_table[DETECT_FILE_DATA].alias = "file_data";
    sigmatch_table[DETECT_FILE_DATA].desc = "make content keywords match on file data";
    sigmatch_table[DETECT_FILE_DATA].url = DOC_URL DOC_VERSION "/rules/http-keywords.html#file-data";
    sigmatch_table[DETECT_FILE_DATA].Setup = DetectFiledataSetup;
#ifdef UNITTESTS
    sigmatch_table[DETECT_FILE_DATA].RegisterTests = DetectFiledataRegisterTests;
#endif
    sigmatch_table[DETECT_FILE_DATA].flags = SIGMATCH_NOOPT;

    DetectAppLayerMpmRegister2("file_data", SIG_FLAG_TOSERVER, 2,
            PrefilterMpmFiledataRegister, NULL,
            ALPROTO_SMTP, 0);
    DetectAppLayerMpmRegister2("file_data", SIG_FLAG_TOCLIENT, 2,
            PrefilterGenericMpmRegister,
            HttpServerBodyGetDataCallback,
            ALPROTO_HTTP, HTP_RESPONSE_BODY);
#ifdef HAVE_RUST
    DetectAppLayerMpmRegister2("file_data", SIG_FLAG_TOSERVER, 2,
            PrefilterMpmFiledataRegister, NULL,
            ALPROTO_SMB, 0);
    DetectAppLayerMpmRegister2("file_data", SIG_FLAG_TOCLIENT, 2,
            PrefilterMpmFiledataRegister, NULL,
            ALPROTO_SMB, 0);
#endif

    DetectAppLayerInspectEngineRegister2("file_data",
            ALPROTO_HTTP, SIG_FLAG_TOCLIENT, HTP_RESPONSE_BODY,
            DetectEngineInspectBufferGeneric, HttpServerBodyGetDataCallback);
    DetectAppLayerInspectEngineRegister2("file_data",
            ALPROTO_SMTP, SIG_FLAG_TOSERVER, 0,
            DetectEngineInspectFiledata, NULL);
    DetectBufferTypeRegisterSetupCallback("file_data",
            DetectFiledataSetupCallback);
#ifdef HAVE_RUST
    DetectAppLayerInspectEngineRegister2("file_data",
            ALPROTO_SMB, SIG_FLAG_TOSERVER, 0,
            DetectEngineInspectFiledata, NULL);
    DetectAppLayerInspectEngineRegister2("file_data",
            ALPROTO_SMB, SIG_FLAG_TOCLIENT, 0,
            DetectEngineInspectFiledata, NULL);
#endif

    DetectBufferTypeSetDescriptionByName("file_data",
            "http response body, smb files or smtp attachments data");

    g_file_data_buffer_id = DetectBufferTypeGetByName("file_data");
}

#define FILEDATA_CONTENT_LIMIT 100000
#define FILEDATA_CONTENT_INSPECT_MIN_SIZE 32768
#define FILEDATA_CONTENT_INSPECT_WINDOW 4096

static void SetupDetectEngineConfig(DetectEngineCtx *de_ctx) {
    if (de_ctx->filedata_config_initialized)
        return;

    /* initialize default */
    for (int i = 0; i < (int)ALPROTO_MAX; i++) {
        de_ctx->filedata_config[i].content_limit = FILEDATA_CONTENT_LIMIT;
        de_ctx->filedata_config[i].content_inspect_min_size = FILEDATA_CONTENT_INSPECT_MIN_SIZE;
        de_ctx->filedata_config[i].content_inspect_window = FILEDATA_CONTENT_INSPECT_WINDOW;
    }

    /* add protocol specific settings here */

    /* SMTP */
    de_ctx->filedata_config[ALPROTO_SMTP].content_limit = smtp_config.content_limit;
    de_ctx->filedata_config[ALPROTO_SMTP].content_inspect_min_size = smtp_config.content_inspect_min_size;
    de_ctx->filedata_config[ALPROTO_SMTP].content_inspect_window = smtp_config.content_inspect_window;

    de_ctx->filedata_config_initialized = true;
}

/**
 * \brief this function is used to parse filedata options
 * \brief into the current signature
 *
 * \param de_ctx pointer to the Detection Engine Context
 * \param s pointer to the Current Signature
 * \param str pointer to the user provided "filestore" option
 *
 * \retval 0 on Success
 * \retval -1 on Failure
 */
static int DetectFiledataSetup (DetectEngineCtx *de_ctx, Signature *s, const char *str)
{
    SCEnter();

    if (!DetectProtoContainsProto(&s->proto, IPPROTO_TCP) ||
        (s->alproto != ALPROTO_UNKNOWN && s->alproto != ALPROTO_HTTP &&
        s->alproto != ALPROTO_SMTP && s->alproto != ALPROTO_SMB)) {
        SCLogError(SC_ERR_CONFLICTING_RULE_KEYWORDS, "rule contains conflicting keywords.");
        return -1;
    }

    if (s->alproto == ALPROTO_HTTP && (s->init_data->init_flags & SIG_FLAG_INIT_FLOW) &&
        (s->flags & SIG_FLAG_TOSERVER) && !(s->flags & SIG_FLAG_TOCLIENT)) {
        SCLogError(SC_ERR_INVALID_SIGNATURE, "Can't use file_data with "
                "flow:to_server or flow:from_client with http.");
        return -1;
    }

    if (s->alproto == ALPROTO_SMTP && (s->init_data->init_flags & SIG_FLAG_INIT_FLOW) &&
        !(s->flags & SIG_FLAG_TOSERVER) && (s->flags & SIG_FLAG_TOCLIENT)) {
        SCLogError(SC_ERR_INVALID_SIGNATURE, "Can't use file_data with "
                "flow:to_client or flow:from_server with smtp.");
        return -1;
    }

    DetectBufferSetActiveList(s, DetectBufferTypeGetByName("file_data"));

    SetupDetectEngineConfig(de_ctx);
    return 0;
}

static void DetectFiledataSetupCallback(const DetectEngineCtx *de_ctx,
                                        Signature *s)
{
    if (s->alproto == ALPROTO_HTTP || s->alproto == ALPROTO_UNKNOWN) {
        AppLayerHtpEnableResponseBodyCallback();
    }


    /* server body needs to be inspected in sync with stream if possible */
    s->init_data->init_flags |= SIG_FLAG_INIT_NEED_FLUSH;

    SCLogDebug("callback invoked by %u", s->id);
}

/* HTTP based detection */

static inline HtpBody *GetResponseBody(htp_tx_t *tx)
{
    HtpTxUserData *htud = (HtpTxUserData *)htp_tx_get_user_data(tx);
    if (htud == NULL) {
        SCLogDebug("no htud");
        return NULL;
    }

    return &htud->response_body;
}

static InspectionBuffer *HttpServerBodyGetDataCallback(DetectEngineThreadCtx *det_ctx,
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

    HtpBody *body = GetResponseBody(tx);
    if (body == NULL) {
        return NULL;
    }

    /* no new data */
    if (body->body_inspected == body->content_len_so_far) {
        SCLogDebug("no new data");
        return NULL;
    }

    HtpBodyChunk *cur = body->first;
    if (cur == NULL) {
        SCLogDebug("No http chunks to inspect for this transacation");
        return NULL;
    }

    SCLogDebug("response.body_limit %u response_body.content_len_so_far %"PRIu64
               ", response.inspect_min_size %"PRIu32", EOF %s, progress > body? %s",
              htp_state->cfg->response.body_limit,
              body->content_len_so_far,
              htp_state->cfg->response.inspect_min_size,
              flags & STREAM_EOF ? "true" : "false",
               (AppLayerParserGetStateProgress(IPPROTO_TCP, ALPROTO_HTTP, tx, flags) > HTP_RESPONSE_BODY) ? "true" : "false");

    if (!htp_state->cfg->http_body_inline) {
        /* inspect the body if the transfer is complete or we have hit
        * our body size limit */
        if ((htp_state->cfg->response.body_limit == 0 ||
             body->content_len_so_far < htp_state->cfg->response.body_limit) &&
            body->content_len_so_far < htp_state->cfg->response.inspect_min_size &&
            !(AppLayerParserGetStateProgress(IPPROTO_TCP, ALPROTO_HTTP, tx, flags) > HTP_RESPONSE_BODY) &&
            !(flags & STREAM_EOF)) {
            SCLogDebug("we still haven't seen the entire response body.  "
                       "Let's defer body inspection till we see the "
                       "entire body.");
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
    if (body->body_inspected > htp_state->cfg->response.inspect_min_size) {
        BUG_ON(body->content_len_so_far < body->body_inspected);
        uint64_t inspect_win = body->content_len_so_far - body->body_inspected;
        SCLogDebug("inspect_win %"PRIu64, inspect_win);
        if (inspect_win < htp_state->cfg->response.inspect_window) {
            uint64_t inspect_short = htp_state->cfg->response.inspect_window - inspect_win;
            if (body->body_inspected < inspect_short)
                offset = 0;
            else
                offset = body->body_inspected - inspect_short;
        } else {
            offset = body->body_inspected - (htp_state->cfg->response.inspect_window / 4);
        }
    }

    const uint8_t *data;
    uint32_t data_len;

    StreamingBufferGetDataAtOffset(body->sb,
            &data, &data_len, offset);
    InspectionBufferSetup(buffer, data, data_len);
    buffer->inspect_offset = offset;

    /* built-in 'transformation' */
    if (htp_state->cfg->swf_decompression_enabled) {
        int swf_file_type = FileIsSwfFile(data, data_len);
        if (swf_file_type == FILE_SWF_ZLIB_COMPRESSION ||
            swf_file_type == FILE_SWF_LZMA_COMPRESSION)
        {
            (void)FileSwfDecompression(data, data_len,
                                       det_ctx,
                                       buffer,
                                       htp_state->cfg->swf_compression_type,
                                       htp_state->cfg->swf_decompress_depth,
                                       htp_state->cfg->swf_compress_depth);
        }
    }

    /* move inspected tracker to end of the data. HtpBodyPrune will consider
     * the window sizes when freeing data */
    body->body_inspected = body->content_len_so_far;
    SCLogDebug("body->body_inspected now: %"PRIu64, body->body_inspected);

    SCReturnPtr(buffer, "InspectionBuffer");
}

/* file API based inspection */

static InspectionBuffer *FiledataGetDataCallback(DetectEngineThreadCtx *det_ctx,
        const DetectEngineTransforms *transforms,
        Flow *f, uint8_t flow_flags, File *cur_file,
        int list_id, int local_file_id, bool first)
{
    SCEnter();

    InspectionBufferMultipleForList *fb = InspectionBufferGetMulti(det_ctx, list_id);
    InspectionBuffer *buffer = InspectionBufferMultipleForListGet(fb, local_file_id);
    if (buffer == NULL)
        return NULL;
    if (!first && buffer->inspect != NULL)
        return buffer;

    const uint64_t file_size = FileDataSize(cur_file);
    const DetectEngineCtx *de_ctx = det_ctx->de_ctx;
    const uint32_t content_limit = de_ctx->filedata_config[f->alproto].content_limit;
    const uint32_t content_inspect_min_size = de_ctx->filedata_config[f->alproto].content_inspect_min_size;
    // TODO this is unused, is that right?
    //const uint32_t content_inspect_window = de_ctx->filedata_config[f->alproto].content_inspect_window;

    SCLogDebug("content_limit %u, content_inspect_min_size %u",
                content_limit, content_inspect_min_size);

    SCLogDebug("file %p size %"PRIu64", state %d", cur_file, file_size, cur_file->state);

    /* no new data */
    if (cur_file->content_inspected == file_size) {
        SCLogDebug("no new data");
        return NULL;
    }

    if (file_size == 0) {
        SCLogDebug("no data to inspect for this transaction");
        return NULL;
    }

    if ((content_limit == 0 || file_size < content_limit) &&
        file_size < content_inspect_min_size &&
        !(flow_flags & STREAM_EOF) && !(cur_file->state > FILE_STATE_OPENED)) {
        SCLogDebug("we still haven't seen the entire content. "
                   "Let's defer content inspection till we see the "
                   "entire content.");
        return NULL;
    }

    const uint8_t *data;
    uint32_t data_len;

    StreamingBufferGetDataAtOffset(cur_file->sb,
            &data, &data_len,
            cur_file->content_inspected);
    InspectionBufferSetup(buffer, data, data_len);
    buffer->inspect_offset = cur_file->content_inspected;
    InspectionBufferApplyTransforms(buffer, transforms);

    /* update inspected tracker */
    cur_file->content_inspected = file_size;
    SCLogDebug("content_inspected %"PRIu64, cur_file->content_inspected);

    SCLogDebug("file_data buffer %p, data %p len %u offset %"PRIu64,
        buffer, buffer->inspect, buffer->inspect_len, buffer->inspect_offset);

    SCReturnPtr(buffer, "InspectionBuffer");
}

static int DetectEngineInspectFiledata(
        DetectEngineCtx *de_ctx, DetectEngineThreadCtx *det_ctx,
        const DetectEngineAppInspectionEngine *engine,
        const Signature *s,
        Flow *f, uint8_t flags, void *alstate, void *txv, uint64_t tx_id)
{
    int r = 0;
    int match = 0;

    // TODO remove
    if (f->alproto == ALPROTO_HTTP) {
        abort();
    }

    const DetectEngineTransforms *transforms = NULL;
    if (!engine->mpm) {
        transforms = engine->v2.transforms;
    }

    FileContainer *ffc = AppLayerParserGetFiles(f->proto, f->alproto,
                                                f->alstate, flags);
    if (ffc == NULL) {
        return DETECT_ENGINE_INSPECT_SIG_NO_MATCH;
    }

    int local_file_id = 0;
    File *file = ffc->head;
    for (; file != NULL; file = file->next) {
        if (file->txid != tx_id)
            continue;

        InspectionBuffer *buffer = FiledataGetDataCallback(det_ctx,
            transforms, f, flags, file, engine->sm_list, local_file_id, false);
        if (buffer == NULL)
            continue;

        bool eof = (file->state == FILE_STATE_CLOSED);
        uint8_t ciflags = eof ? DETECT_CI_FLAGS_END : 0;
        if (buffer->inspect_offset == 0)
            ciflags |= DETECT_CI_FLAGS_START;

        det_ctx->buffer_offset = 0;
        det_ctx->discontinue_matching = 0;
        det_ctx->inspection_recursion_counter = 0;
        match = DetectEngineContentInspection(de_ctx, det_ctx, s, engine->smd,
                                              NULL, f,
                                              (uint8_t *)buffer->inspect,
                                              buffer->inspect_len,
                                              buffer->inspect_offset, ciflags,
                                              DETECT_ENGINE_CONTENT_INSPECTION_MODE_STATE);
        if (match == 1) {
            r = 1;
            break;
        }
        local_file_id++;
    }

    if (r == 1)
        return DETECT_ENGINE_INSPECT_SIG_MATCH;
    else
        return DETECT_ENGINE_INSPECT_SIG_NO_MATCH;
}

typedef struct PrefilterMpmFiledata {
    int list_id;
    const MpmCtx *mpm_ctx;
    const DetectEngineTransforms *transforms;
} PrefilterMpmFiledata;

/** \brief Filedata Filedata Mpm prefilter callback
 *
 *  \param det_ctx detection engine thread ctx
 *  \param p packet to inspect
 *  \param f flow to inspect
 *  \param txv tx to inspect
 *  \param pectx inspection context
 */
static void PrefilterTxFiledata(DetectEngineThreadCtx *det_ctx,
        const void *pectx,
        Packet *p, Flow *f, void *txv,
        const uint64_t idx, const uint8_t flags)
{
    SCEnter();

    const PrefilterMpmFiledata *ctx = (const PrefilterMpmFiledata *)pectx;
    const MpmCtx *mpm_ctx = ctx->mpm_ctx;
    const int list_id = ctx->list_id;

    FileContainer *ffc = AppLayerParserGetFiles(f->proto, f->alproto,
                                                f->alstate, flags);
    int local_file_id = 0;
    if (ffc != NULL) {
        File *file = ffc->head;
        for (; file != NULL; file = file->next) {
            if (file->txid != idx)
                continue;

            InspectionBuffer *buffer = FiledataGetDataCallback(det_ctx,
                    ctx->transforms, f, flags, file, list_id, local_file_id, true);
            if (buffer == NULL)
                continue;

            if (buffer->inspect_len >= mpm_ctx->minlen) {
                (void)mpm_table[mpm_ctx->mpm_type].Search(mpm_ctx,
                        &det_ctx->mtcu, &det_ctx->pmq,
                        buffer->inspect, buffer->inspect_len);
            }
        }
    }
}

static void PrefilterMpmFiledataFree(void *ptr)
{
    SCFree(ptr);
}

int PrefilterMpmFiledataRegister(DetectEngineCtx *de_ctx,
        SigGroupHead *sgh, MpmCtx *mpm_ctx,
        const DetectMpmAppLayerRegistery *mpm_reg, int list_id)
{
    PrefilterMpmFiledata *pectx = SCCalloc(1, sizeof(*pectx));
    if (pectx == NULL)
        return -1;
    pectx->list_id = list_id;
    pectx->mpm_ctx = mpm_ctx;
    pectx->transforms = &mpm_reg->v2.transforms;

    return PrefilterAppendTxEngine(de_ctx, sgh, PrefilterTxFiledata,
            mpm_reg->v2.alproto, mpm_reg->v2.tx_min_progress,
            pectx, PrefilterMpmFiledataFree, mpm_reg->pname);
}

#ifdef UNITTESTS
#include "tests/detect-file-data.c"
#endif
