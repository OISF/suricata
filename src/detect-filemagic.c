/* Copyright (C) 2007-2023 Open Information Security Foundation
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
#include "detect-content.h"

#include "detect-engine.h"
#include "detect-engine-mpm.h"
#include "detect-engine-prefilter.h"
#include "detect-engine-content-inspection.h"
#include "detect-engine-file.h"

#include "flow.h"
#include "flow-var.h"
#include "flow-util.h"

#include "util-debug.h"
#include "util-spm-bm.h"
#include "util-magic.h"
#include "util-print.h"

#include "util-unittest.h"
#include "util-unittest-helper.h"
#include "util-profiling.h"

#include "app-layer.h"
#include "app-layer-parser.h"

#include "stream-tcp.h"

#include "detect-file-data.h"
#include "detect-filemagic.h"

#include "conf.h"

#ifndef HAVE_MAGIC

static int DetectFilemagicSetupNoSupport (DetectEngineCtx *de_ctx, Signature *s, const char *str)
{
    SCLogError("no libmagic support built in, needed for filemagic keyword");
    return -1;
}

/**
 * \brief Registration function for keyword: filemagic
 */
void DetectFilemagicRegister(void)
{
    sigmatch_table[DETECT_FILEMAGIC].name = "filemagic";
    sigmatch_table[DETECT_FILEMAGIC].desc = "match on the information libmagic returns about a file";
    sigmatch_table[DETECT_FILEMAGIC].url = "/rules/file-keywords.html#filemagic";
    sigmatch_table[DETECT_FILEMAGIC].Setup = DetectFilemagicSetupNoSupport;
    sigmatch_table[DETECT_FILEMAGIC].flags = SIGMATCH_QUOTES_MANDATORY|SIGMATCH_HANDLE_NEGATION;
}

#else /* HAVE_MAGIC */

typedef struct DetectFilemagicThreadData {
    magic_t ctx;
} DetectFilemagicThreadData;

static int DetectFilemagicSetup(DetectEngineCtx *, Signature *, const char *);
static int g_file_match_list_id = 0;

static int DetectFilemagicSetupSticky(DetectEngineCtx *de_ctx, Signature *s, const char *str);
static int g_file_magic_buffer_id = 0;

static int PrefilterMpmFilemagicRegister(DetectEngineCtx *de_ctx, SigGroupHead *sgh,
        MpmCtx *mpm_ctx, const DetectBufferMpmRegistry *mpm_reg, int list_id);
static uint8_t DetectEngineInspectFilemagic(DetectEngineCtx *de_ctx, DetectEngineThreadCtx *det_ctx,
        const DetectEngineAppInspectionEngine *engine, const Signature *s, Flow *f, uint8_t flags,
        void *alstate, void *txv, uint64_t tx_id);

/**
 * \brief Registration function for keyword: filemagic
 */
void DetectFilemagicRegister(void)
{
    sigmatch_table[DETECT_FILEMAGIC].name = "filemagic";
    sigmatch_table[DETECT_FILEMAGIC].desc = "match on the information libmagic returns about a file";
    sigmatch_table[DETECT_FILEMAGIC].url = "/rules/file-keywords.html#filemagic";
    sigmatch_table[DETECT_FILEMAGIC].Setup = DetectFilemagicSetup;
    sigmatch_table[DETECT_FILEMAGIC].flags = SIGMATCH_QUOTES_MANDATORY|SIGMATCH_HANDLE_NEGATION;
    sigmatch_table[DETECT_FILEMAGIC].alternative = DETECT_FILE_MAGIC;

    sigmatch_table[DETECT_FILE_MAGIC].name = "file.magic";
    sigmatch_table[DETECT_FILE_MAGIC].desc = "sticky buffer to match on the file magic";
    sigmatch_table[DETECT_FILE_MAGIC].url = "/rules/file-keywords.html#filemagic";
    sigmatch_table[DETECT_FILE_MAGIC].Setup = DetectFilemagicSetupSticky;
    sigmatch_table[DETECT_FILE_MAGIC].flags = SIGMATCH_NOOPT|SIGMATCH_INFO_STICKY_BUFFER;

    filehandler_table[DETECT_FILE_MAGIC].name = "file.magic",
    filehandler_table[DETECT_FILE_MAGIC].priority = 2;
    filehandler_table[DETECT_FILE_MAGIC].PrefilterFn = PrefilterMpmFilemagicRegister;
    filehandler_table[DETECT_FILE_MAGIC].Callback = DetectEngineInspectFilemagic;

    g_file_match_list_id = DetectBufferTypeRegister("files");

    DetectBufferTypeSetDescriptionByName("file.magic", "file magic");
    DetectBufferTypeSupportsMultiInstance("file.magic");

    g_file_magic_buffer_id = DetectBufferTypeGetByName("file.magic");
    SCLogDebug("registering filemagic rule option");
}

#define FILEMAGIC_MIN_SIZE  512

/**
 *  \brief run the magic check
 *
 *  \param file the file
 *
 *  \retval -1 error
 *  \retval 0 ok
 */
int FilemagicThreadLookup(magic_t *ctx, File *file)
{
    if (ctx == NULL || file == NULL || FileDataSize(file) == 0) {
        SCReturnInt(-1);
    }

    const uint8_t *data = NULL;
    uint32_t data_len = 0;
    uint64_t offset = 0;

    StreamingBufferGetData(file->sb,
                           &data, &data_len, &offset);
    if (offset == 0) {
        if (FileDataSize(file) >= FILEMAGIC_MIN_SIZE) {
            file->magic = MagicThreadLookup(ctx, data, data_len);
        } else if (file->state >= FILE_STATE_CLOSED) {
            file->magic = MagicThreadLookup(ctx, data, data_len);
        }
    }
    SCReturnInt(0);
}

static void *DetectFilemagicThreadInit(void *data /*@unused@*/)
{
    DetectFilemagicThreadData *t = SCCalloc(1, sizeof(DetectFilemagicThreadData));
    if (unlikely(t == NULL)) {
        SCLogError("couldn't alloc ctx memory");
        return NULL;
    }

    t->ctx = MagicInitContext();
    if (t->ctx == NULL)
        goto error;

    return (void *)t;

error:
    if (t->ctx)
        magic_close(t->ctx);
    SCFree(t);
    return NULL;
}

static void DetectFilemagicThreadFree(void *ctx)
{
    if (ctx != NULL) {
        DetectFilemagicThreadData *t = (DetectFilemagicThreadData *)ctx;
        if (t->ctx)
            magic_close(t->ctx);
        SCFree(t);
    }
}

/**
 * \brief this function is used to parse filemagic options
 * \brief into the current signature
 *
 * \param de_ctx pointer to the Detection Engine Context
 * \param s pointer to the Current Signature
 * \param str pointer to the user provided "filemagic" option
 *
 * \retval 0 on Success
 * \retval -1 on Failure
 */
static int DetectFilemagicSetup (DetectEngineCtx *de_ctx, Signature *s, const char *str)
{
    if (s->init_data->transforms.cnt) {
        SCLogError("previous transforms not consumed before 'filemagic'");
        SCReturnInt(-1);
    }
    s->init_data->list = DETECT_SM_LIST_NOTSET;
    s->file_flags |= (FILE_SIG_NEED_FILE | FILE_SIG_NEED_MAGIC);
    if ((s->init_data->init_flags & SIG_FLAG_INIT_BIDIR_TOCLIENT) == 0) {
        s->init_data->init_flags |= SIG_FLAG_INIT_BIDIR_STREAMING_TOSERVER;
    }

    if (DetectContentSetup(de_ctx, s, str) < 0) {
        return -1;
    }

    SigMatch *sm = DetectGetLastSMFromLists(s, DETECT_CONTENT, -1);
    if (sm == NULL)
        return -1;

    DetectContentData *cd = (DetectContentData *)sm->ctx;
    if (DetectContentConvertToNocase(de_ctx, cd) != 0)
        return -1;
    if (DetectEngineContentModifierBufferSetup(
                de_ctx, s, NULL, DETECT_FILE_MAGIC, g_file_magic_buffer_id, s->alproto) < 0)
        return -1;

    if (de_ctx->filemagic_thread_ctx_id == -1) {
        de_ctx->filemagic_thread_ctx_id = DetectRegisterThreadCtxFuncs(
                de_ctx, "filemagic", DetectFilemagicThreadInit, NULL, DetectFilemagicThreadFree, 1);
        if (de_ctx->filemagic_thread_ctx_id == -1)
            return -1;
    }
    return 0;
}

/* file.magic implementation */

/**
 * \brief this function setup the file.magic keyword used in the rule
 *
 * \param de_ctx   Pointer to the Detection Engine Context
 * \param s        Pointer to the Signature to which the current keyword belongs
 * \param str      Should hold an empty string always
 *
 * \retval 0       On success
 */
static int DetectFilemagicSetupSticky(DetectEngineCtx *de_ctx, Signature *s, const char *str)
{
    if (DetectBufferSetActiveList(de_ctx, s, g_file_magic_buffer_id) < 0)
        return -1;

    if (de_ctx->filemagic_thread_ctx_id == -1) {
        de_ctx->filemagic_thread_ctx_id = DetectRegisterThreadCtxFuncs(
                de_ctx, "filemagic", DetectFilemagicThreadInit, NULL, DetectFilemagicThreadFree, 1);
        if (de_ctx->filemagic_thread_ctx_id == -1)
            return -1;
    }
    return 0;
}

static InspectionBuffer *FilemagicGetDataCallback(DetectEngineThreadCtx *det_ctx,
        const DetectEngineTransforms *transforms, Flow *f, uint8_t flow_flags, File *cur_file,
        int list_id, int local_file_id)
{
    SCEnter();

    InspectionBuffer *buffer = InspectionBufferMultipleForListGet(det_ctx, list_id, local_file_id);
    if (buffer == NULL)
        return NULL;
    if (buffer->initialized)
        return buffer;

    if (cur_file->magic == NULL) {
        DetectFilemagicThreadData *tfilemagic =
                (DetectFilemagicThreadData *)DetectThreadCtxGetKeywordThreadCtx(
                        det_ctx, det_ctx->de_ctx->filemagic_thread_ctx_id);
        if (tfilemagic == NULL) {
            InspectionBufferSetupMultiEmpty(buffer);
            return NULL;
        }

        FilemagicThreadLookup(&tfilemagic->ctx, cur_file);
    }
    if (cur_file->magic == NULL) {
        return NULL;
    }

    const uint8_t *data = (const uint8_t *)cur_file->magic;
    uint32_t data_len = (uint32_t)strlen(cur_file->magic);

    InspectionBufferSetupMulti(buffer, transforms, data, data_len);

    SCReturnPtr(buffer, "InspectionBuffer");
}

static uint8_t DetectEngineInspectFilemagic(DetectEngineCtx *de_ctx, DetectEngineThreadCtx *det_ctx,
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

    uint8_t r = DETECT_ENGINE_INSPECT_SIG_NO_MATCH;
    int local_file_id = 0;
    for (File *file = ffc->head; file != NULL; file = file->next) {
        InspectionBuffer *buffer = FilemagicGetDataCallback(
                det_ctx, transforms, f, flags, file, engine->sm_list, local_file_id);
        if (buffer == NULL)
            continue;

        const bool match = DetectEngineContentInspection(de_ctx, det_ctx, s, engine->smd, NULL, f,
                buffer->inspect, buffer->inspect_len, buffer->inspect_offset,
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

typedef struct PrefilterMpmFilemagic {
    int list_id;
    const MpmCtx *mpm_ctx;
    const DetectEngineTransforms *transforms;
} PrefilterMpmFilemagic;

/** \brief Filedata Filedata Mpm prefilter callback
 *
 *  \param det_ctx detection engine thread ctx
 *  \param p packet to inspect
 *  \param f flow to inspect
 *  \param txv tx to inspect
 *  \param pectx inspection context
 */
static void PrefilterTxFilemagic(DetectEngineThreadCtx *det_ctx, const void *pectx, Packet *p,
        Flow *f, void *txv, const uint64_t idx, const AppLayerTxData *txd, const uint8_t flags)
{
    SCEnter();

    if (!AppLayerParserHasFilesInDir(txd, flags))
        return;

    const PrefilterMpmFilemagic *ctx = (const PrefilterMpmFilemagic *)pectx;
    const MpmCtx *mpm_ctx = ctx->mpm_ctx;
    const int list_id = ctx->list_id;

    AppLayerGetFileState files = AppLayerParserGetTxFiles(f, txv, flags);
    FileContainer *ffc = files.fc;
    if (ffc != NULL) {
        int local_file_id = 0;
        for (File *file = ffc->head; file != NULL; file = file->next) {
            InspectionBuffer *buffer = FilemagicGetDataCallback(
                    det_ctx, ctx->transforms, f, flags, file, list_id, local_file_id);
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

static void PrefilterMpmFilemagicFree(void *ptr)
{
    SCFree(ptr);
}

static int PrefilterMpmFilemagicRegister(DetectEngineCtx *de_ctx, SigGroupHead *sgh,
        MpmCtx *mpm_ctx, const DetectBufferMpmRegistry *mpm_reg, int list_id)
{
    PrefilterMpmFilemagic *pectx = SCCalloc(1, sizeof(*pectx));
    if (pectx == NULL)
        return -1;
    pectx->list_id = list_id;
    pectx->mpm_ctx = mpm_ctx;
    pectx->transforms = &mpm_reg->transforms;

    return PrefilterAppendTxEngine(de_ctx, sgh, PrefilterTxFilemagic,
            mpm_reg->app_v2.alproto, mpm_reg->app_v2.tx_min_progress,
            pectx, PrefilterMpmFilemagicFree, mpm_reg->pname);
}

#endif /* HAVE_MAGIC */
