/* Copyright (C) 2022 Open Information Security Foundation
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
#include "detect-engine-mpm.h"
#include "detect-engine-prefilter.h"
#include "detect-engine-content-inspection.h"
#include "rust.h"
#include "util-mimetype.h"

static int DetectFileMimetypeSetup(DetectEngineCtx *de_ctx, Signature *s, const char *str);
static int g_file_mimetype_buffer_id = 0;

static int PrefilterMpmFileMimetypeRegister(DetectEngineCtx *de_ctx, SigGroupHead *sgh,
        MpmCtx *mpm_ctx, const DetectBufferMpmRegistery *mpm_reg, int list_id);
static uint8_t DetectEngineInspectFileMimetype(DetectEngineCtx *de_ctx,
        DetectEngineThreadCtx *det_ctx, const DetectEngineAppInspectionEngine *engine,
        const Signature *s, Flow *f, uint8_t flags, void *alstate, void *txv, uint64_t tx_id);

void DetectFileMimetypeRegister(void)
{
    sigmatch_table[DETECT_FILE_MIMETYPE].name = "file.mime_type";
    sigmatch_table[DETECT_FILE_MIMETYPE].desc = "sticky buffer to match on file mime type";
    sigmatch_table[DETECT_FILE_MIMETYPE].url = "/rules/file-keywords.html#file-mime-type";
    sigmatch_table[DETECT_FILE_MIMETYPE].Setup = DetectFileMimetypeSetup;
    sigmatch_table[DETECT_FILE_MIMETYPE].flags = SIGMATCH_NOOPT | SIGMATCH_INFO_STICKY_BUFFER;

    AppProto protos_ts[] = { ALPROTO_HTTP1, ALPROTO_SMTP, ALPROTO_FTP, ALPROTO_FTPDATA, ALPROTO_SMB,
        ALPROTO_NFS, 0 };
    AppProto protos_tc[] = { ALPROTO_HTTP1, ALPROTO_FTP, ALPROTO_FTPDATA, ALPROTO_SMB, ALPROTO_NFS,
        0 };

    for (int i = 0; protos_ts[i] != 0; i++) {
        DetectAppLayerInspectEngineRegister2("file.mime_type", protos_ts[i], SIG_FLAG_TOSERVER, 0,
                DetectEngineInspectFileMimetype, NULL);

        DetectAppLayerMpmRegister2("file.mime_type", SIG_FLAG_TOSERVER, 2,
                PrefilterMpmFileMimetypeRegister, NULL, protos_ts[i], 0);
    }
    for (int i = 0; protos_tc[i] != 0; i++) {
        DetectAppLayerInspectEngineRegister2("file.mime_type", protos_tc[i], SIG_FLAG_TOCLIENT, 0,
                DetectEngineInspectFileMimetype, NULL);

        DetectAppLayerMpmRegister2("file.mime_type", SIG_FLAG_TOCLIENT, 2,
                PrefilterMpmFileMimetypeRegister, NULL, protos_tc[i], 0);
    }

    DetectBufferTypeSetDescriptionByName("file.mime_type", "file mime type");

    g_file_mimetype_buffer_id = DetectBufferTypeGetByName("file.mime_type");

    SCLogDebug("registering file mime type rule option");
    return;
}

static int DetectFileMimetypeSetup(DetectEngineCtx *de_ctx, Signature *s, const char *str)
{
    if (DetectBufferSetActiveList(s, g_file_mimetype_buffer_id) < 0)
        return -1;
    s->file_flags |= (FILE_SIG_NEED_FILE); /* FIXME do we need a custom need flag . */
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
    uint32_t data_len = strlen(cur_file->mimetype);

    InspectionBufferSetupMulti(buffer, transforms, data, data_len);

    SCReturnPtr(buffer, "InspectionBuffer");
}

typedef struct PrefilterMpmFileMimetype {
    int list_id;
    const MpmCtx *mpm_ctx;
    const DetectEngineTransforms *transforms;
} PrefilterMpmFileMimetype;

/** \brief Filedata Filedata Mpm prefilter callback
 *
 *  \param det_ctx detection engine thread ctx
 *  \param p packet to inspect
 *  \param f flow to inspect
 *  \param txv tx to inspect
 *  \param pectx inspection context
 */
static void PrefilterTxFileMimetype(DetectEngineThreadCtx *det_ctx, const void *pectx, Packet *p,
        Flow *f, void *txv, const uint64_t idx, const uint8_t flags)
{
    SCEnter();

    const PrefilterMpmFileMimetype *ctx = (const PrefilterMpmFileMimetype *)pectx;
    const MpmCtx *mpm_ctx = ctx->mpm_ctx;
    const int list_id = ctx->list_id;

    FileContainer *ffc = AppLayerParserGetFiles(f, flags);
    if (ffc != NULL) {
        int local_file_id = 0;
        for (File *file = ffc->head; file != NULL; file = file->next) {
            if (file->txid != idx)
                continue;

            InspectionBuffer *buffer = FileMimetypeGetDataCallback(
                    det_ctx, ctx->transforms, f, flags, file, list_id, local_file_id, true);
            if (buffer == NULL)
                continue;

            if (buffer->inspect_len >= mpm_ctx->minlen) {
                (void)mpm_table[mpm_ctx->mpm_type].Search(mpm_ctx, &det_ctx->mtcu, &det_ctx->pmq,
                        buffer->inspect, buffer->inspect_len);
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
        MpmCtx *mpm_ctx, const DetectBufferMpmRegistery *mpm_reg, int list_id)
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

static uint8_t DetectEngineInspectFileMimetype(DetectEngineCtx *de_ctx,
        DetectEngineThreadCtx *det_ctx, const DetectEngineAppInspectionEngine *engine,
        const Signature *s, Flow *f, uint8_t flags, void *alstate, void *txv, uint64_t tx_id)
{
    const DetectEngineTransforms *transforms = NULL;
    if (!engine->mpm) {
        transforms = engine->v2.transforms;
    }

    FileContainer *ffc = AppLayerParserGetFiles(f, flags);
    if (ffc == NULL) {
        return DETECT_ENGINE_INSPECT_SIG_NO_MATCH;
    }

    uint8_t r = DETECT_ENGINE_INSPECT_SIG_NO_MATCH;
    int local_file_id = 0;
    for (File *file = ffc->head; file != NULL; file = file->next) {
        if (file->txid != tx_id)
            continue;

        InspectionBuffer *buffer = FileMimetypeGetDataCallback(
                det_ctx, transforms, f, flags, file, engine->sm_list, local_file_id, false);
        if (buffer == NULL)
            continue;

        det_ctx->buffer_offset = 0;
        det_ctx->discontinue_matching = 0;
        det_ctx->inspection_recursion_counter = 0;
        int match = DetectEngineContentInspection(de_ctx, det_ctx, s, engine->smd, NULL, f,
                (uint8_t *)buffer->inspect, buffer->inspect_len, buffer->inspect_offset,
                DETECT_CI_FLAGS_SINGLE, DETECT_ENGINE_CONTENT_INSPECTION_MODE_STATE);
        if (match == 1) {
            return DETECT_ENGINE_INSPECT_SIG_MATCH;
        } else {
            r = DETECT_ENGINE_INSPECT_SIG_CANT_MATCH_FILES;
        }
        local_file_id++;
    }
    return r;
}
