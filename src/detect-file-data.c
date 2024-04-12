/* Copyright (C) 2007-2022 Open Information Security Foundation
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
#include "decode.h"

#include "detect.h"
#include "detect-parse.h"

#include "detect-engine.h"
#include "detect-engine-mpm.h"
#include "detect-engine-state.h"
#include "detect-engine-prefilter.h"
#include "detect-engine-content-inspection.h"
#include "detect-engine-file.h"
#include "detect-file-data.h"

#include "app-layer.h"
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
#include "util-profiling.h"

static int DetectFiledataSetup (DetectEngineCtx *, Signature *, const char *);
#ifdef UNITTESTS
static void DetectFiledataRegisterTests(void);
#endif
static void DetectFiledataSetupCallback(const DetectEngineCtx *de_ctx,
                                        Signature *s);
static int g_file_data_buffer_id = 0;

/* file API */
int PrefilterMpmFiledataRegister(DetectEngineCtx *de_ctx, SigGroupHead *sgh, MpmCtx *mpm_ctx,
        const DetectBufferMpmRegistry *mpm_reg, int list_id);

/**
 * \brief Registration function for keyword: file_data
 */
void DetectFiledataRegister(void)
{
    sigmatch_table[DETECT_FILE_DATA].name = "file.data";
    sigmatch_table[DETECT_FILE_DATA].alias = "file_data";
    sigmatch_table[DETECT_FILE_DATA].desc = "make content keywords match on file data";
    sigmatch_table[DETECT_FILE_DATA].url = "/rules/file-keywords.html#file-data";
    sigmatch_table[DETECT_FILE_DATA].Setup = DetectFiledataSetup;
#ifdef UNITTESTS
    sigmatch_table[DETECT_FILE_DATA].RegisterTests = DetectFiledataRegisterTests;
#endif
    sigmatch_table[DETECT_FILE_DATA].flags = SIGMATCH_NOOPT;

    filehandler_table[DETECT_FILE_DATA].name = "file_data";
    filehandler_table[DETECT_FILE_DATA].priority = 2;
    filehandler_table[DETECT_FILE_DATA].PrefilterFn = PrefilterMpmFiledataRegister;
    filehandler_table[DETECT_FILE_DATA].Callback = DetectEngineInspectFiledata;

    DetectBufferTypeRegisterSetupCallback("file_data", DetectFiledataSetupCallback);

    DetectBufferTypeSetDescriptionByName("file_data", "data from tracked files");
    DetectBufferTypeSupportsMultiInstance("file_data");

    g_file_data_buffer_id = DetectBufferTypeGetByName("file_data");
}

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

    if (!DetectProtoContainsProto(&s->proto, IPPROTO_TCP)) {
        SCLogError("The 'file_data' keyword cannot be used with non-TCP protocols");
        return -1;
    }

    if (s->alproto != ALPROTO_UNKNOWN && !AppLayerParserSupportsFiles(IPPROTO_TCP, s->alproto)) {
        SCLogError("The 'file_data' keyword cannot be used with TCP protocol %s",
                AppLayerGetProtoName(s->alproto));
        return -1;
    }

    if (s->alproto == ALPROTO_SMTP && (s->init_data->init_flags & SIG_FLAG_INIT_FLOW) &&
        !(s->flags & SIG_FLAG_TOSERVER) && (s->flags & SIG_FLAG_TOCLIENT)) {
        SCLogError("The 'file-data' keyword cannot be used with SMTP flow:to_client or "
                   "flow:from_server.");
        return -1;
    }

    if (DetectBufferSetActiveList(de_ctx, s, DetectBufferTypeGetByName("file_data")) < 0)
        return -1;

    s->init_data->init_flags |= SIG_FLAG_INIT_FILEDATA;
    if ((s->init_data->init_flags & SIG_FLAG_INIT_BIDIR_TOCLIENT) == 0) {
        s->init_data->init_flags |= SIG_FLAG_INIT_BIDIR_STREAMING_TOSERVER;
    }
    SetupDetectEngineConfig(de_ctx);
    return 0;
}

static void DetectFiledataSetupCallback(const DetectEngineCtx *de_ctx,
                                        Signature *s)
{
    if (s->alproto == ALPROTO_HTTP1 || s->alproto == ALPROTO_UNKNOWN ||
            s->alproto == ALPROTO_HTTP) {
        AppLayerHtpEnableResponseBodyCallback();
    }

    /* server body needs to be inspected in sync with stream if possible */
    s->init_data->init_flags |= SIG_FLAG_INIT_NEED_FLUSH;

    SCLogDebug("callback invoked by %u", s->id);
}

/* common */

static void PrefilterMpmFiledataFree(void *ptr)
{
    SCFree(ptr);
}

/* file API based inspection */

static inline InspectionBuffer *FiledataWithXformsGetDataCallback(DetectEngineThreadCtx *det_ctx,
        const DetectEngineTransforms *transforms, const int list_id, int local_file_id,
        InspectionBuffer *base_buffer)
{
    InspectionBuffer *buffer = InspectionBufferMultipleForListGet(det_ctx, list_id, local_file_id);
    if (buffer == NULL) {
        SCLogDebug("list_id: %d: no buffer", list_id);
        return NULL;
    }
    if (buffer->initialized) {
        SCLogDebug("list_id: %d: returning %p", list_id, buffer);
        return buffer;
    }

    InspectionBufferSetupMulti(buffer, transforms, base_buffer->inspect, base_buffer->inspect_len);
    buffer->inspect_offset = base_buffer->inspect_offset;
    SCLogDebug("xformed buffer %p size %u", buffer, buffer->inspect_len);
    SCReturnPtr(buffer, "InspectionBuffer");
}

static InspectionBuffer *FiledataGetDataCallback(DetectEngineThreadCtx *det_ctx,
        const DetectEngineTransforms *transforms, Flow *f, uint8_t flow_flags, File *cur_file,
        const int list_id, const int base_id, int local_file_id, void *txv)
{
    SCEnter();
    SCLogDebug("starting: list_id %d base_id %d", list_id, base_id);

    InspectionBuffer *buffer = InspectionBufferMultipleForListGet(det_ctx, base_id, local_file_id);
    SCLogDebug("base: buffer %p", buffer);
    if (buffer == NULL)
        return NULL;
    if (base_id != list_id && buffer->inspect != NULL) {
        SCLogDebug("handle xform %s", (list_id != base_id) ? "true" : "false");
        return FiledataWithXformsGetDataCallback(
                det_ctx, transforms, list_id, local_file_id, buffer);
    }
    if (buffer->initialized) {
        SCLogDebug("base_id: %d, not first: use %p", base_id, buffer);
        return buffer;
    }

    const uint64_t file_size = FileDataSize(cur_file);
    const DetectEngineCtx *de_ctx = det_ctx->de_ctx;
    const uint32_t content_limit = de_ctx->filedata_config[f->alproto].content_limit;
    const uint32_t content_inspect_min_size =
            de_ctx->filedata_config[f->alproto].content_inspect_min_size;

    SCLogDebug("[list %d] content_limit %u, content_inspect_min_size %u", list_id, content_limit,
            content_inspect_min_size);

    SCLogDebug("[list %d] file %p size %" PRIu64 ", state %d", list_id, cur_file, file_size,
            cur_file->state);

    /* no new data */
    if (cur_file->content_inspected == file_size) {
        SCLogDebug("no new data");
        goto empty_return;
    }

    if (file_size == 0) {
        SCLogDebug("no data to inspect for this transaction");
        goto empty_return;
    }

    SCLogDebug("offset %" PRIu64, StreamingBufferGetOffset(cur_file->sb));
    SCLogDebug("size %" PRIu64, cur_file->size);
    SCLogDebug("content_inspected %" PRIu64, cur_file->content_inspected);
    SCLogDebug("inspect_window %" PRIu32, cur_file->inspect_window);
    SCLogDebug("inspect_min_size %" PRIu32, cur_file->inspect_min_size);

    bool ips = false;
    uint64_t offset = 0;
    if (f->alproto == ALPROTO_HTTP1) {

        htp_tx_t *tx = txv;
        HtpState *htp_state = f->alstate;
        ips = htp_state->cfg->http_body_inline;

        const bool body_done = AppLayerParserGetStateProgress(IPPROTO_TCP, ALPROTO_HTTP1, tx,
                                       flow_flags) > HTP_RESPONSE_BODY;

        SCLogDebug("response.body_limit %u file_size %" PRIu64
                   ", cur_file->inspect_min_size %" PRIu32 ", EOF %s, progress > body? %s",
                htp_state->cfg->response.body_limit, file_size, cur_file->inspect_min_size,
                flow_flags & STREAM_EOF ? "true" : "false", BOOL2STR(body_done));

        if (!htp_state->cfg->http_body_inline) {
            /* inspect the body if the transfer is complete or we have hit
             * our body size limit */
            if ((htp_state->cfg->response.body_limit == 0 ||
                        file_size < htp_state->cfg->response.body_limit) &&
                    file_size < cur_file->inspect_min_size && !body_done &&
                    !(flow_flags & STREAM_EOF)) {
                SCLogDebug("we still haven't seen the entire response body.  "
                           "Let's defer body inspection till we see the "
                           "entire body.");
                goto empty_return;
            }
            SCLogDebug("inline and we're continuing");
        }

        bool force = (flow_flags & STREAM_EOF) || (cur_file->state > FILE_STATE_OPENED) ||
                     body_done || htp_state->cfg->http_body_inline;
        /* get the inspect buffer
         *
         * make sure that we have at least the configured inspect_win size.
         * If we have more, take at least 1/4 of the inspect win size before
         * the new data.
         */
        if (cur_file->content_inspected == 0) {
            if (!force && file_size < cur_file->inspect_min_size) {
                SCLogDebug("skip as file_size %" PRIu64 " < inspect_min_size %u", file_size,
                        cur_file->inspect_min_size);
                goto empty_return;
            }
        } else {
            uint64_t new_data = file_size - cur_file->content_inspected;
            BUG_ON(new_data == 0);
            if (new_data < cur_file->inspect_window) {
                uint64_t inspect_short = cur_file->inspect_window - new_data;
                if (cur_file->content_inspected < inspect_short) {
                    offset = 0;
                    SCLogDebug("offset %" PRIu64, offset);
                } else {
                    offset = cur_file->content_inspected - inspect_short;
                    SCLogDebug("offset %" PRIu64, offset);
                }
            } else {
                BUG_ON(cur_file->content_inspected == 0);
                uint32_t margin = cur_file->inspect_window / 4;
                if ((uint64_t)margin <= cur_file->content_inspected) {
                    offset = cur_file->content_inspected - (cur_file->inspect_window / 4);
                } else {
                    offset = 0;
                }
                SCLogDebug("offset %" PRIu64 " (data from offset %" PRIu64 ")", offset,
                        file_size - offset);
            }
        }

    } else {
        if ((content_limit == 0 || file_size < content_limit) &&
                file_size < content_inspect_min_size && !(flow_flags & STREAM_EOF) &&
                !(cur_file->state > FILE_STATE_OPENED)) {
            SCLogDebug("we still haven't seen the entire content. "
                       "Let's defer content inspection till we see the "
                       "entire content. We've seen %ld and need at least %d",
                    file_size, content_inspect_min_size);
            goto empty_return;
        }
        offset = cur_file->content_inspected;
    }

    const uint8_t *data;
    uint32_t data_len;

    SCLogDebug("Fetching data at offset: %ld", offset);
    StreamingBufferGetDataAtOffset(cur_file->sb, &data, &data_len, offset);
    SCLogDebug("data_len %u", data_len);
    /* update inspected tracker */
    buffer->inspect_offset = offset;

    if (ips && file_size < cur_file->inspect_min_size) {
        // don't update content_inspected yet
    } else {
        SCLogDebug("content inspected: %" PRIu64, cur_file->content_inspected);
        cur_file->content_inspected = MAX(cur_file->content_inspected, offset + data_len);
        SCLogDebug("content inspected: %" PRIu64, cur_file->content_inspected);
    }

    InspectionBufferSetupMulti(buffer, NULL, data, data_len);
    SCLogDebug("[list %d] [before] buffer offset %" PRIu64 "; buffer len %" PRIu32
               "; data_len %" PRIu32 "; file_size %" PRIu64,
            list_id, buffer->inspect_offset, buffer->inspect_len, data_len, file_size);

    if (f->alproto == ALPROTO_HTTP1 && flow_flags & STREAM_TOCLIENT) {
        HtpState *htp_state = f->alstate;
        /* built-in 'transformation' */
        if (htp_state->cfg->swf_decompression_enabled) {
            int swf_file_type = FileIsSwfFile(data, data_len);
            if (swf_file_type == FILE_SWF_ZLIB_COMPRESSION ||
                    swf_file_type == FILE_SWF_LZMA_COMPRESSION) {
                SCLogDebug("decompressing ...");
                (void)FileSwfDecompression(data, data_len, det_ctx, buffer,
                        htp_state->cfg->swf_compression_type, htp_state->cfg->swf_decompress_depth,
                        htp_state->cfg->swf_compress_depth);
                SCLogDebug("uncompressed buffer %p size %u; buf: \"%s\"", buffer,
                        buffer->inspect_len, (char *)buffer->inspect);
            }
        }
    }

    SCLogDebug("content inspected: %" PRIu64, cur_file->content_inspected);

    /* get buffer for the list id if it is different from the base id */
    if (list_id != base_id) {
        SCLogDebug("regular %d has been set up: now handle xforms id %d", base_id, list_id);
        InspectionBuffer *tbuffer = FiledataWithXformsGetDataCallback(
                det_ctx, transforms, list_id, local_file_id, buffer);
        SCReturnPtr(tbuffer, "InspectionBuffer");
    }
    SCReturnPtr(buffer, "InspectionBuffer");

empty_return:
    InspectionBufferSetupMultiEmpty(buffer);
    return NULL;
}

uint8_t DetectEngineInspectFiledata(DetectEngineCtx *de_ctx, DetectEngineThreadCtx *det_ctx,
        const DetectEngineAppInspectionEngine *engine, const Signature *s, Flow *f, uint8_t flags,
        void *alstate, void *txv, uint64_t tx_id)
{
    const DetectEngineTransforms *transforms = NULL;
    if (!engine->mpm) {
        transforms = engine->v2.transforms;
    }

    AppLayerGetFileState files = AppLayerParserGetTxFiles(f, txv, flags);
    FileContainer *ffc = files.fc;
    if (ffc == NULL) {
        return DETECT_ENGINE_INSPECT_SIG_CANT_MATCH_FILES;
    }

    int local_file_id = 0;
    File *file = ffc->head;
    for (; file != NULL; file = file->next) {
        InspectionBuffer *buffer = FiledataGetDataCallback(det_ctx, transforms, f, flags, file,
                engine->sm_list, engine->sm_list_base, local_file_id, txv);
        if (buffer == NULL)
            continue;

        bool eof = (file->state == FILE_STATE_CLOSED);
        uint8_t ciflags = eof ? DETECT_CI_FLAGS_END : 0;
        if (buffer->inspect_offset == 0)
            ciflags |= DETECT_CI_FLAGS_START;

        const bool match = DetectEngineContentInspection(de_ctx, det_ctx, s, engine->smd, NULL, f,
                buffer->inspect, buffer->inspect_len, buffer->inspect_offset, ciflags,
                DETECT_ENGINE_CONTENT_INSPECTION_MODE_STATE);
        if (match) {
            return DETECT_ENGINE_INSPECT_SIG_MATCH;
        }
        local_file_id++;
    }

    return DETECT_ENGINE_INSPECT_SIG_NO_MATCH;
}

/** \brief Filedata Filedata Mpm prefilter callback
 *
 *  \param det_ctx detection engine thread ctx
 *  \param pectx inspection context
 *  \param p packet to inspect
 *  \param f flow to inspect
 *  \param txv tx to inspect
 *  \param idx transaction id
 *  \param flags STREAM_* flags including direction
 */
static void PrefilterTxFiledata(DetectEngineThreadCtx *det_ctx, const void *pectx, Packet *p,
        Flow *f, void *txv, const uint64_t idx, const AppLayerTxData *txd, const uint8_t flags)
{
    SCEnter();

    if (!AppLayerParserHasFilesInDir(txd, flags))
        return;

    const PrefilterMpmFiledata *ctx = (const PrefilterMpmFiledata *)pectx;
    const MpmCtx *mpm_ctx = ctx->mpm_ctx;
    const int list_id = ctx->list_id;

    AppLayerGetFileState files = AppLayerParserGetTxFiles(f, txv, flags);
    FileContainer *ffc = files.fc;
    if (ffc != NULL) {
        int local_file_id = 0;
        for (File *file = ffc->head; file != NULL; file = file->next) {
            InspectionBuffer *buffer = FiledataGetDataCallback(det_ctx, ctx->transforms, f, flags,
                    file, list_id, ctx->base_list_id, local_file_id, txv);
            if (buffer == NULL)
                continue;
            SCLogDebug("[%" PRIu64 "] buffer size %u", p->pcap_cnt, buffer->inspect_len);

            if (buffer->inspect_len >= mpm_ctx->minlen) {
                uint32_t prev_rule_id_array_cnt = det_ctx->pmq.rule_id_array_cnt;
                (void)mpm_table[mpm_ctx->mpm_type].Search(mpm_ctx, &det_ctx->mtc, &det_ctx->pmq,
                        buffer->inspect, buffer->inspect_len);
                PREFILTER_PROFILING_ADD_BYTES(det_ctx, buffer->inspect_len);

                if (det_ctx->pmq.rule_id_array_cnt > prev_rule_id_array_cnt) {
                    SCLogDebug(
                            "%u matches", det_ctx->pmq.rule_id_array_cnt - prev_rule_id_array_cnt);
                }
            }
            local_file_id++;
        }
    }
}

int PrefilterMpmFiledataRegister(DetectEngineCtx *de_ctx, SigGroupHead *sgh, MpmCtx *mpm_ctx,
        const DetectBufferMpmRegistry *mpm_reg, int list_id)
{
    PrefilterMpmFiledata *pectx = SCCalloc(1, sizeof(*pectx));
    if (pectx == NULL)
        return -1;
    pectx->list_id = list_id;
    pectx->base_list_id = mpm_reg->sm_list_base;
    pectx->mpm_ctx = mpm_ctx;
    pectx->transforms = &mpm_reg->transforms;

    return PrefilterAppendTxEngine(de_ctx, sgh, PrefilterTxFiledata,
            mpm_reg->app_v2.alproto, mpm_reg->app_v2.tx_min_progress,
            pectx, PrefilterMpmFiledataFree, mpm_reg->pname);
}

#ifdef UNITTESTS
#include "tests/detect-file-data.c"
#endif
