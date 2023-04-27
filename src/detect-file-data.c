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
#include "util-profiling.h"

static int DetectFiledataSetup (DetectEngineCtx *, Signature *, const char *);
#ifdef UNITTESTS
static void DetectFiledataRegisterTests(void);
#endif
static void DetectFiledataSetupCallback(const DetectEngineCtx *de_ctx,
                                        Signature *s);
static int g_file_data_buffer_id = 0;

static inline HtpBody *GetResponseBody(htp_tx_t *tx);

/* file API */
static uint8_t DetectEngineInspectFiledata(DetectEngineCtx *de_ctx, DetectEngineThreadCtx *det_ctx,
        const DetectEngineAppInspectionEngine *engine, const Signature *s, Flow *f, uint8_t flags,
        void *alstate, void *txv, uint64_t tx_id);
int PrefilterMpmFiledataRegister(DetectEngineCtx *de_ctx,
        SigGroupHead *sgh, MpmCtx *mpm_ctx,
        const DetectBufferMpmRegistery *mpm_reg, int list_id);

/**
 * \brief Registration function for keyword: file_data
 */
void DetectFiledataRegister(void)
{
    sigmatch_table[DETECT_FILE_DATA].name = "file.data";
    sigmatch_table[DETECT_FILE_DATA].alias = "file_data";
    sigmatch_table[DETECT_FILE_DATA].desc = "make content keywords match on file data";
    sigmatch_table[DETECT_FILE_DATA].url = "/rules/http-keywords.html#file-data";
    sigmatch_table[DETECT_FILE_DATA].Setup = DetectFiledataSetup;
#ifdef UNITTESTS
    sigmatch_table[DETECT_FILE_DATA].RegisterTests = DetectFiledataRegisterTests;
#endif
    sigmatch_table[DETECT_FILE_DATA].flags = SIGMATCH_NOOPT;

    DetectAppLayerMpmRegister2("file_data", SIG_FLAG_TOSERVER, 2,
            PrefilterMpmFiledataRegister, NULL,
            ALPROTO_SMTP, 0);
    DetectAppLayerMpmRegister2("file_data", SIG_FLAG_TOCLIENT, 2, PrefilterMpmFiledataRegister,
            NULL, ALPROTO_HTTP1, HTP_RESPONSE_BODY);
    DetectAppLayerMpmRegister2("file_data", SIG_FLAG_TOSERVER, 2, PrefilterMpmFiledataRegister,
            NULL, ALPROTO_HTTP1, HTP_REQUEST_BODY);
    DetectAppLayerMpmRegister2("file_data", SIG_FLAG_TOSERVER, 2,
            PrefilterMpmFiledataRegister, NULL,
            ALPROTO_SMB, 0);
    DetectAppLayerMpmRegister2("file_data", SIG_FLAG_TOCLIENT, 2,
            PrefilterMpmFiledataRegister, NULL,
            ALPROTO_SMB, 0);
    DetectAppLayerMpmRegister2("file_data", SIG_FLAG_TOSERVER, 2,
            PrefilterMpmFiledataRegister, NULL,
            ALPROTO_HTTP2, HTTP2StateDataClient);
    DetectAppLayerMpmRegister2("file_data", SIG_FLAG_TOCLIENT, 2,
            PrefilterMpmFiledataRegister, NULL,
            ALPROTO_HTTP2, HTTP2StateDataServer);
    DetectAppLayerMpmRegister2(
            "file_data", SIG_FLAG_TOSERVER, 2, PrefilterMpmFiledataRegister, NULL, ALPROTO_NFS, 0);
    DetectAppLayerMpmRegister2(
            "file_data", SIG_FLAG_TOCLIENT, 2, PrefilterMpmFiledataRegister, NULL, ALPROTO_NFS, 0);
    DetectAppLayerMpmRegister2("file_data", SIG_FLAG_TOSERVER, 2, PrefilterMpmFiledataRegister,
            NULL, ALPROTO_FTPDATA, 0);
    DetectAppLayerMpmRegister2("file_data", SIG_FLAG_TOCLIENT, 2, PrefilterMpmFiledataRegister,
            NULL, ALPROTO_FTPDATA, 0);
    DetectAppLayerMpmRegister2(
            "file_data", SIG_FLAG_TOSERVER, 2, PrefilterMpmFiledataRegister, NULL, ALPROTO_FTP, 0);
    DetectAppLayerMpmRegister2(
            "file_data", SIG_FLAG_TOCLIENT, 2, PrefilterMpmFiledataRegister, NULL, ALPROTO_FTP, 0);

    DetectAppLayerInspectEngineRegister2("file_data", ALPROTO_HTTP1, SIG_FLAG_TOCLIENT,
            HTP_RESPONSE_BODY, DetectEngineInspectFiledata, NULL);
    DetectAppLayerInspectEngineRegister2("file_data", ALPROTO_HTTP1, SIG_FLAG_TOSERVER,
            HTP_REQUEST_BODY, DetectEngineInspectFiledata, NULL);
    DetectAppLayerInspectEngineRegister2("file_data",
            ALPROTO_SMTP, SIG_FLAG_TOSERVER, 0,
            DetectEngineInspectFiledata, NULL);
    DetectBufferTypeRegisterSetupCallback("file_data",
            DetectFiledataSetupCallback);
    DetectAppLayerInspectEngineRegister2("file_data",
            ALPROTO_SMB, SIG_FLAG_TOSERVER, 0,
            DetectEngineInspectFiledata, NULL);
    DetectAppLayerInspectEngineRegister2("file_data",
            ALPROTO_SMB, SIG_FLAG_TOCLIENT, 0,
            DetectEngineInspectFiledata, NULL);
    DetectAppLayerInspectEngineRegister2("file_data",
            ALPROTO_HTTP2, SIG_FLAG_TOSERVER, HTTP2StateDataClient,
            DetectEngineInspectFiledata, NULL);
    DetectAppLayerInspectEngineRegister2("file_data",
            ALPROTO_HTTP2, SIG_FLAG_TOCLIENT, HTTP2StateDataServer,
            DetectEngineInspectFiledata, NULL);
    DetectAppLayerInspectEngineRegister2(
            "file_data", ALPROTO_NFS, SIG_FLAG_TOSERVER, 0, DetectEngineInspectFiledata, NULL);
    DetectAppLayerInspectEngineRegister2(
            "file_data", ALPROTO_NFS, SIG_FLAG_TOCLIENT, 0, DetectEngineInspectFiledata, NULL);
    DetectAppLayerInspectEngineRegister2(
            "file_data", ALPROTO_FTPDATA, SIG_FLAG_TOSERVER, 0, DetectEngineInspectFiledata, NULL);
    DetectAppLayerInspectEngineRegister2(
            "file_data", ALPROTO_FTPDATA, SIG_FLAG_TOCLIENT, 0, DetectEngineInspectFiledata, NULL);
    DetectAppLayerInspectEngineRegister2(
            "file_data", ALPROTO_FTP, SIG_FLAG_TOSERVER, 0, DetectEngineInspectFiledata, NULL);
    DetectAppLayerInspectEngineRegister2(
            "file_data", ALPROTO_FTP, SIG_FLAG_TOCLIENT, 0, DetectEngineInspectFiledata, NULL);

    DetectBufferTypeSetDescriptionByName("file_data", "data from tracked files");

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

    if (!DetectProtoContainsProto(&s->proto, IPPROTO_TCP) ||
            (s->alproto != ALPROTO_UNKNOWN && s->alproto != ALPROTO_HTTP1 &&
                    s->alproto != ALPROTO_SMTP && s->alproto != ALPROTO_SMB &&
                    s->alproto != ALPROTO_HTTP2 && s->alproto != ALPROTO_FTP &&
                    s->alproto != ALPROTO_FTPDATA && s->alproto != ALPROTO_HTTP &&
                    s->alproto != ALPROTO_NFS)) {
        SCLogError("rule contains conflicting keywords.");
        return -1;
    }

    if (s->alproto == ALPROTO_SMTP && (s->init_data->init_flags & SIG_FLAG_INIT_FLOW) &&
        !(s->flags & SIG_FLAG_TOSERVER) && (s->flags & SIG_FLAG_TOCLIENT)) {
        SCLogError("Can't use file_data with "
                   "flow:to_client or flow:from_server with smtp.");
        return -1;
    }

    if (DetectBufferSetActiveList(de_ctx, s, DetectBufferTypeGetByName("file_data")) < 0)
        return -1;

    s->init_data->init_flags |= SIG_FLAG_INIT_FILEDATA;
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

typedef struct PrefilterMpmFiledata {
    int list_id;
    int base_list_id;
    const MpmCtx *mpm_ctx;
    const DetectEngineTransforms *transforms;
} PrefilterMpmFiledata;

static void PrefilterMpmFiledataFree(void *ptr)
{
    SCFree(ptr);
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
        const int list_id, const int base_id, int local_file_id)
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
    const uint32_t content_inspect_min_size = de_ctx->filedata_config[f->alproto].content_inspect_min_size;
    // TODO this is unused, is that right?
    //const uint32_t content_inspect_window = de_ctx->filedata_config[f->alproto].content_inspect_window;

    SCLogDebug("[list %d] content_limit %u, content_inspect_min_size %u", list_id, content_limit,
            content_inspect_min_size);

    SCLogDebug("[list %d] file %p size %" PRIu64 ", state %d", list_id, cur_file, file_size,
            cur_file->state);

    /* no new data */
    if (cur_file->content_inspected == file_size) {
        SCLogDebug("no new data");
        InspectionBufferSetupMultiEmpty(buffer);
        return NULL;
    }

    if (file_size == 0) {
        SCLogDebug("no data to inspect for this transaction");
        InspectionBufferSetupMultiEmpty(buffer);
        return NULL;
    }

    if ((content_limit == 0 || file_size < content_limit) &&
        file_size < content_inspect_min_size &&
        !(flow_flags & STREAM_EOF) && !(cur_file->state > FILE_STATE_OPENED)) {
        SCLogDebug("we still haven't seen the entire content. "
                   "Let's defer content inspection till we see the "
                   "entire content.");
        InspectionBufferSetupMultiEmpty(buffer);
        return NULL;
    }

    const uint8_t *data;
    uint32_t data_len;

    StreamingBufferGetDataAtOffset(cur_file->sb,
            &data, &data_len,
            cur_file->content_inspected);
    InspectionBufferSetupMulti(buffer, NULL, data, data_len);
    SCLogDebug("[list %d] [before] buffer offset %" PRIu64 "; buffer len %" PRIu32
               "; data_len %" PRIu32 "; file_size %" PRIu64,
            list_id, buffer->inspect_offset, buffer->inspect_len, data_len, file_size);
    buffer->inspect_offset = cur_file->content_inspected;

    /* update inspected tracker */
    cur_file->content_inspected = buffer->inspect_len + buffer->inspect_offset;
    SCLogDebug("content inspected: %" PRIu64, cur_file->content_inspected);

    /* get buffer for the list id if it is different from the base id */
    if (list_id != base_id) {
        SCLogDebug("regular %d has been set up: now handle xforms id %d", base_id, list_id);
        InspectionBuffer *tbuffer = FiledataWithXformsGetDataCallback(
                det_ctx, transforms, list_id, local_file_id, buffer);
        SCReturnPtr(tbuffer, "InspectionBuffer");
    } else {
        SCLogDebug("regular buffer %p size %u", buffer, buffer->inspect_len);
        SCReturnPtr(buffer, "InspectionBuffer");
    }
}

static uint8_t DetectEngineInspectFiledata(DetectEngineCtx *de_ctx, DetectEngineThreadCtx *det_ctx,
        const DetectEngineAppInspectionEngine *engine, const Signature *s, Flow *f, uint8_t flags,
        void *alstate, void *txv, uint64_t tx_id)
{
    int r = 0;
    int match = 0;

    const DetectEngineTransforms *transforms = NULL;
    if (!engine->mpm) {
        transforms = engine->v2.transforms;
    }

    AppLayerGetFileState files = AppLayerParserGetTxFiles(f, alstate, txv, flags);
    FileContainer *ffc = files.fc;
    if (ffc == NULL) {
        return DETECT_ENGINE_INSPECT_SIG_CANT_MATCH_FILES;
    }

    int local_file_id = 0;
    File *file = ffc->head;
    for (; file != NULL; file = file->next) {
        InspectionBuffer *buffer = FiledataGetDataCallback(det_ctx, transforms, f, flags, file,
                engine->sm_list, engine->sm_list_base, local_file_id);
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

    AppLayerGetFileState files = AppLayerParserGetTxFiles(f, f->alstate, txv, flags);
    FileContainer *ffc = files.fc;
    if (ffc != NULL) {
        int local_file_id = 0;
        for (File *file = ffc->head; file != NULL; file = file->next) {
            InspectionBuffer *buffer = FiledataGetDataCallback(det_ctx, ctx->transforms, f, flags,
                    file, list_id, ctx->base_list_id, local_file_id);
            if (buffer == NULL)
                continue;

            if (buffer->inspect_len >= mpm_ctx->minlen) {
                (void)mpm_table[mpm_ctx->mpm_type].Search(mpm_ctx,
                        &det_ctx->mtcu, &det_ctx->pmq,
                        buffer->inspect, buffer->inspect_len);
                PREFILTER_PROFILING_ADD_BYTES(det_ctx, buffer->inspect_len);
            }
            local_file_id++;
        }
    }
}

int PrefilterMpmFiledataRegister(DetectEngineCtx *de_ctx,
        SigGroupHead *sgh, MpmCtx *mpm_ctx,
        const DetectBufferMpmRegistery *mpm_reg, int list_id)
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
