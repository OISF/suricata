/* Copyright (C) 2025 Open Information Security Foundation
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
 * \author Eric Leblond <el@stamus-networks.com>
 *
 */

#include "suricata-common.h"
#include "detect-file-mimetype.h"
#include "detect-engine.h"
#include "detect-engine-buffer.h"
#include "detect-engine-mpm.h"
#include "detect-engine-prefilter.h"
#include "detect-engine-content-inspection.h"
#include "detect-parse.h"
#include "detect-file-data.h"
#include "rust.h"
#include "util-mimetype.h"
#include "util-profiling.h"
#include "app-layer-parser.h"

#include "conf.h"

#ifndef HAVE_MIMETYPE

static int DetectFileMimetypeSetupNoSupport(DetectEngineCtx *de_ctx, Signature *s, const char *str)
{
    SCLogError("no mimetype support built in, needed for file.mimetype keyword");
    return -1;
}

/**
 * \brief Registration function for keyword: filemagic
 */
void DetectFileMimetypeRegister(void)
{
    sigmatch_table[DETECT_FILE_MIMETYPE].name = "file.mimetype";
    sigmatch_table[DETECT_FILE_MIMETYPE].desc = "sticky buffer to match on file mime type";
    sigmatch_table[DETECT_FILE_MIMETYPE].url = "/rules/file-keywords.html#file_mimetype";
    sigmatch_table[DETECT_FILE_MIMETYPE].Setup = DetectFileMimetypeSetupNoSupport;
    sigmatch_table[DETECT_FILE_MIMETYPE].flags = SIGMATCH_NOOPT | SIGMATCH_INFO_STICKY_BUFFER;
}

#else /* HAVE_MIMETYPE */

static int g_file_match_list_id = 0;

static int DetectFileMimetypeSetup(DetectEngineCtx *de_ctx, Signature *s, const char *str);
static int g_file_mimetype_buffer_id = 0;

static int PrefilterMpmFileMimetypeRegister(DetectEngineCtx *de_ctx, SigGroupHead *sgh,
        MpmCtx *mpm_ctx, const DetectBufferMpmRegistry *mpm_reg, int list_id);
static unsigned char DetectEngineInspectFileMimetype(DetectEngineCtx *de_ctx,
        DetectEngineThreadCtx *det_ctx, const DetectEngineAppInspectionEngine *engine,
        const Signature *s, Flow *f, uint8_t flags, void *alstate, void *txv, uint64_t tx_id);

void DetectFileMimetypeRegister(void)
{
    sigmatch_table[DETECT_FILE_MIMETYPE].name = "file.mime_type";
    sigmatch_table[DETECT_FILE_MIMETYPE].desc = "sticky buffer to match on file mime type";
    sigmatch_table[DETECT_FILE_MIMETYPE].url = "/rules/file-keywords.html#file_mimetype";
    sigmatch_table[DETECT_FILE_MIMETYPE].Setup = DetectFileMimetypeSetup;
    sigmatch_table[DETECT_FILE_MIMETYPE].flags = SIGMATCH_NOOPT | SIGMATCH_INFO_STICKY_BUFFER;

    filehandler_table[DETECT_FILE_MIMETYPE].name = "file.mime_type",
    filehandler_table[DETECT_FILE_MIMETYPE].priority = 2;
    filehandler_table[DETECT_FILE_MIMETYPE].PrefilterFn = PrefilterMpmFileMimetypeRegister;
    filehandler_table[DETECT_FILE_MIMETYPE].Callback = DetectEngineInspectFileMimetype;

    g_file_match_list_id = DetectBufferTypeRegister("files");

    DetectBufferTypeSetDescriptionByName("file.mime_type", "file mime_type");
    DetectBufferTypeSupportsMultiInstance("file.mime_type");

    g_file_mimetype_buffer_id = DetectBufferTypeGetByName("file.mime_type");

    SCLogDebug("registering file mime type rule option");
}

static int DetectFileMimetypeSetup(DetectEngineCtx *de_ctx, Signature *s, const char *str)
{
    if (SCDetectBufferSetActiveList(de_ctx, s, g_file_mimetype_buffer_id) < 0)
        return -1;
    s->file_flags |= (FILE_SIG_NEED_FILE | FILE_SIG_NEED_MIMETYPE);
    return 0;
}

static InspectionBuffer *FileMimetypeGetDataCallback(DetectEngineThreadCtx *det_ctx,
        const DetectEngineTransforms *transforms, Flow *f, uint8_t flow_flags, File *cur_file,
        int list_id, int local_file_id, bool first)
{
    SCEnter();

    InspectionBuffer *buffer = InspectionBufferMultipleForListGet(det_ctx, list_id, local_file_id);
    if (buffer == NULL)
        return NULL;
    if (!first && buffer->inspect != NULL)
        return buffer;

    if (cur_file->mimetype == NULL)
        FileMimetypeLookup(cur_file);
    if (cur_file->mimetype == NULL)
        return NULL;

    const uint8_t *data = (uint8_t *)cur_file->mimetype;
    uint32_t data_len = (uint32_t)strlen(cur_file->mimetype);

    InspectionBufferSetupMulti(det_ctx, buffer, transforms, data, data_len);

    SCReturnPtr(buffer, "InspectionBuffer");
}

typedef struct PrefilterMpmFileMimetype {
    int list_id;
    const MpmCtx *mpm_ctx;
    const DetectEngineTransforms *transforms;
} PrefilterMpmFileMimetype;

/** \brief Filemimetype Filemimetype Mpm prefilter callback
 *
 *  \param det_ctx detection engine thread ctx
 *  \param pectx inspection context
 *  \param p packet to inspect
 *  \param f flow to inspect
 *  \param txv tx to inspect
 *  \param idx transaction id
 *  \param flags STREAM_* flags including direction
 */
static void PrefilterTxFileMimetype(DetectEngineThreadCtx *det_ctx, const void *pectx, Packet *p,
        Flow *f, void *txv, const uint64_t idx, const AppLayerTxData *txd, const uint8_t flags)
{
    SCEnter();

    const PrefilterMpmFileMimetype *ctx = (const PrefilterMpmFileMimetype *)pectx;
    const MpmCtx *mpm_ctx = ctx->mpm_ctx;
    const int list_id = ctx->list_id;

    AppLayerGetFileState files = AppLayerParserGetTxFiles(f, txv, flags);
    FileContainer *ffc = files.fc;
    if (ffc != NULL) {
        int local_file_id = 0;
        for (File *file = ffc->head; file != NULL; file = file->next) {
            InspectionBuffer *buffer = FileMimetypeGetDataCallback(
                    det_ctx, ctx->transforms, f, flags, file, list_id, local_file_id, txv);
            if (buffer == NULL)
                continue;

            if (buffer->inspect_len >= mpm_ctx->minlen) {
                (void)mpm_table[mpm_ctx->mpm_type].Search(mpm_ctx, &det_ctx->mtc, &det_ctx->pmq,
                        buffer->inspect, buffer->inspect_len);
                PREFILTER_PROFILING_ADD_BYTES(det_ctx, buffer->inspect_len);
            }
            local_file_id++;
        }
    }
}

static void PrefilterMpmFileMimetypeFree(void *ptr)
{
    SCFree(ptr);
}

static int PrefilterMpmFileMimetypeRegister(DetectEngineCtx *de_ctx, SigGroupHead *sgh,
        MpmCtx *mpm_ctx, const DetectBufferMpmRegistry *mpm_reg, int list_id)
{
    PrefilterMpmFileMimetype *pectx = SCCalloc(1, sizeof(*pectx));
    if (pectx == NULL)
        return -1;
    pectx->list_id = list_id;
    pectx->mpm_ctx = mpm_ctx;
    pectx->transforms = &mpm_reg->transforms;

    return PrefilterAppendTxEngine(de_ctx, sgh, PrefilterTxFileMimetype, mpm_reg->app_v2.alproto,
            mpm_reg->app_v2.tx_min_progress, pectx, PrefilterMpmFileMimetypeFree, mpm_reg->pname);
}

static unsigned char DetectEngineInspectFileMimetype(DetectEngineCtx *de_ctx,
        DetectEngineThreadCtx *det_ctx, const DetectEngineAppInspectionEngine *engine,
        const Signature *s, Flow *f, uint8_t flags, void *alstate, void *txv, uint64_t tx_id)
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

    uint8_t r = DETECT_ENGINE_INSPECT_SIG_NO_MATCH;
    int local_file_id = 0;
    for (File *file = ffc->head; file != NULL; file = file->next) {
        InspectionBuffer *buffer = FileMimetypeGetDataCallback(
                det_ctx, transforms, f, flags, file, engine->sm_list, local_file_id, txv);
        if (buffer == NULL) {
            local_file_id++;
            continue;
        }

        const bool match = DetectEngineContentInspection(de_ctx, det_ctx, s, engine->smd, NULL, f,
                (uint8_t *)buffer->inspect, buffer->inspect_len, buffer->inspect_offset,
                DETECT_CI_FLAGS_SINGLE, DETECT_ENGINE_CONTENT_INSPECTION_MODE_STATE);
        if (match) {
            return DETECT_ENGINE_INSPECT_SIG_MATCH;
        } else {
            r = DETECT_ENGINE_INSPECT_SIG_CANT_MATCH_FILES;
        }
        local_file_id++;
    }
    return r;
}

#endif /* HAVE_MIMETYPE */
