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
 * \author Pablo Rincon <pablo.rincon.crespo@gmail.com>
 *
 */

#include "suricata-common.h"
#include "threads.h"
#include "decode.h"

#include "detect.h"

#include "detect-engine.h"
#include "detect-engine-mpm.h"
#include "detect-engine-state.h"
#include "detect-engine-file.h"
#include "detect-engine-prefilter.h"
#include "detect-engine-content-inspection.h"

#include "detect-parse.h"
#include "detect-content.h"
#include "detect-file-data.h"

#include "flow.h"
#include "flow-var.h"
#include "flow-util.h"

#include "util-debug.h"
#include "util-spm-bm.h"
#include "util-unittest.h"
#include "util-unittest-helper.h"
#include "util-profiling.h"

#include "app-layer.h"
#include "app-layer-htp.h"

#include "stream-tcp.h"

#include "detect-filename.h"
#include "app-layer-parser.h"

static int DetectFileextSetup(DetectEngineCtx *de_ctx, Signature *s, const char *str);
static int DetectFilenameSetup (DetectEngineCtx *, Signature *, const char *);
static int DetectFilenameSetupSticky(DetectEngineCtx *de_ctx, Signature *s, const char *str);
#ifdef UNITTESTS
static void DetectFilenameRegisterTests(void);
#endif
static int g_file_match_list_id = 0;
static int g_file_name_buffer_id = 0;

static int PrefilterMpmFilenameRegister(DetectEngineCtx *de_ctx, SigGroupHead *sgh, MpmCtx *mpm_ctx,
        const DetectBufferMpmRegistry *mpm_reg, int list_id);
static uint8_t DetectEngineInspectFilename(DetectEngineCtx *de_ctx, DetectEngineThreadCtx *det_ctx,
        const DetectEngineAppInspectionEngine *engine, const Signature *s, Flow *f, uint8_t flags,
        void *alstate, void *txv, uint64_t tx_id);

/**
 * \brief Registration function for keyword: filename
 */
void DetectFilenameRegister(void)
{
    sigmatch_table[DETECT_FILENAME].name = "filename";
    sigmatch_table[DETECT_FILENAME].desc = "match on the file name";
    sigmatch_table[DETECT_FILENAME].url = "/rules/file-keywords.html#filename";
    sigmatch_table[DETECT_FILENAME].Setup = DetectFilenameSetup;
#ifdef UNITTESTS
    sigmatch_table[DETECT_FILENAME].RegisterTests = DetectFilenameRegisterTests;
#endif
    sigmatch_table[DETECT_FILENAME].flags = SIGMATCH_QUOTES_OPTIONAL|SIGMATCH_HANDLE_NEGATION;
    sigmatch_table[DETECT_FILENAME].alternative = DETECT_FILE_NAME;

    sigmatch_table[DETECT_FILEEXT].name = "fileext";
    sigmatch_table[DETECT_FILEEXT].desc = "match on the extension of a file name";
    sigmatch_table[DETECT_FILEEXT].url = "/rules/file-keywords.html#fileext";
    sigmatch_table[DETECT_FILEEXT].Setup = DetectFileextSetup;
    sigmatch_table[DETECT_FILEEXT].flags = SIGMATCH_QUOTES_OPTIONAL | SIGMATCH_HANDLE_NEGATION;
    sigmatch_table[DETECT_FILEEXT].alternative = DETECT_FILE_NAME;

    sigmatch_table[DETECT_FILE_NAME].name = "file.name";
    sigmatch_table[DETECT_FILE_NAME].desc = "sticky buffer to match on the file name";
    sigmatch_table[DETECT_FILE_NAME].url = "/rules/file-keywords.html#filename";
    sigmatch_table[DETECT_FILE_NAME].Setup = DetectFilenameSetupSticky;
    sigmatch_table[DETECT_FILE_NAME].flags = SIGMATCH_NOOPT|SIGMATCH_INFO_STICKY_BUFFER;

    DetectBufferTypeSetDescriptionByName("file.name", "file name");

    g_file_match_list_id = DetectBufferTypeRegister("files");
    g_file_name_buffer_id = DetectBufferTypeRegister("file.name");

    SCLogDebug("registering filename rule option");
    filehandler_table[DETECT_FILENAME].name = "files";
    filehandler_table[DETECT_FILENAME].priority = 0;
    filehandler_table[DETECT_FILENAME].PrefilterFn = NULL;
    filehandler_table[DETECT_FILENAME].Callback = DetectFileInspectGeneric;

    filehandler_table[DETECT_FILE_NAME].name = "file.name";
    filehandler_table[DETECT_FILE_NAME].priority = 2;
    filehandler_table[DETECT_FILE_NAME].PrefilterFn = PrefilterMpmFilenameRegister;
    filehandler_table[DETECT_FILE_NAME].Callback = DetectEngineInspectFilename;

    DetectBufferTypeSupportsMultiInstance("file.name");
}

static int DetectFileextSetup(DetectEngineCtx *de_ctx, Signature *s, const char *str)
{
    if (s->init_data->transforms.cnt) {
        SCLogError("previous transforms not consumed before 'fileext'");
        SCReturnInt(-1);
    }
    s->init_data->list = DETECT_SM_LIST_NOTSET;
    s->file_flags |= (FILE_SIG_NEED_FILE | FILE_SIG_NEED_FILENAME);
    if ((s->init_data->init_flags & SIG_FLAG_INIT_BIDIR_TOCLIENT) == 0) {
        s->init_data->init_flags |= SIG_FLAG_INIT_BIDIR_STREAMING_TOSERVER;
    }

    size_t dotstr_len = strlen(str) + 2;
    char *dotstr = SCCalloc(1, dotstr_len);
    if (dotstr == NULL)
        return -1;
    dotstr[0] = '.';
    strlcat(dotstr, str, dotstr_len);

    if (DetectContentSetup(de_ctx, s, dotstr) < 0) {
        SCFree(dotstr);
        return -1;
    }
    SCFree(dotstr);

    SigMatch *sm = DetectGetLastSMFromLists(s, DETECT_CONTENT, -1);
    if (sm == NULL)
        return -1;

    DetectContentData *cd = (DetectContentData *)sm->ctx;
    cd->flags |= DETECT_CONTENT_ENDS_WITH;
    if (DetectContentConvertToNocase(de_ctx, cd) != 0)
        return -1;
    if (DetectEngineContentModifierBufferSetup(
                de_ctx, s, NULL, DETECT_FILE_NAME, g_file_name_buffer_id, s->alproto) < 0)
        return -1;

    return 0;
}
/**
 * \brief this function is used to parse filename options
 * \brief into the current signature
 *
 * \param de_ctx pointer to the Detection Engine Context
 * \param s pointer to the Current Signature
 * \param str pointer to the user provided "filename" option
 *
 * \retval 0 on Success
 * \retval -1 on Failure
 */
static int DetectFilenameSetup (DetectEngineCtx *de_ctx, Signature *s, const char *str)
{
    if (s->init_data->transforms.cnt) {
        SCLogError("previous transforms not consumed before 'filename'");
        SCReturnInt(-1);
    }
    s->init_data->list = DETECT_SM_LIST_NOTSET;
    s->file_flags |= (FILE_SIG_NEED_FILE | FILE_SIG_NEED_FILENAME);
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
                de_ctx, s, NULL, DETECT_FILE_NAME, g_file_name_buffer_id, s->alproto) < 0)
        return -1;

    return 0;
}

/* file.name implementation */

/**
 * \brief this function setup the file.data keyword used in the rule
 *
 * \param de_ctx   Pointer to the Detection Engine Context
 * \param s        Pointer to the Signature to which the current keyword belongs
 * \param str      Should hold an empty string always
 *
 * \retval 0       On success
 */
static int DetectFilenameSetupSticky(DetectEngineCtx *de_ctx, Signature *s, const char *str)
{
    if (DetectBufferSetActiveList(de_ctx, s, g_file_name_buffer_id) < 0)
        return -1;
    s->file_flags |= (FILE_SIG_NEED_FILE | FILE_SIG_NEED_FILENAME);
    if ((s->init_data->init_flags & SIG_FLAG_INIT_BIDIR_TOCLIENT) == 0) {
        s->init_data->init_flags |= SIG_FLAG_INIT_BIDIR_STREAMING_TOSERVER;
    }
    return 0;
}

static InspectionBuffer *FilenameGetDataCallback(DetectEngineThreadCtx *det_ctx,
        const DetectEngineTransforms *transforms, Flow *f, uint8_t flow_flags, File *cur_file,
        int list_id, int local_file_id)
{
    SCEnter();

    InspectionBuffer *buffer = InspectionBufferMultipleForListGet(det_ctx, list_id, local_file_id);
    if (buffer == NULL)
        return NULL;
    if (buffer->initialized)
        return buffer;

    const uint8_t *data = cur_file->name;
    uint32_t data_len = cur_file->name_len;

    InspectionBufferSetupMulti(buffer, transforms, data, data_len);

    SCReturnPtr(buffer, "InspectionBuffer");
}

static uint8_t DetectEngineInspectFilename(DetectEngineCtx *de_ctx, DetectEngineThreadCtx *det_ctx,
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
        InspectionBuffer *buffer = FilenameGetDataCallback(
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

typedef struct PrefilterMpmFilename {
    int list_id;
    const MpmCtx *mpm_ctx;
    const DetectEngineTransforms *transforms;
} PrefilterMpmFilename;

/** \brief Filedata Filedata Mpm prefilter callback
 *
 *  \param det_ctx detection engine thread ctx
 *  \param p packet to inspect
 *  \param f flow to inspect
 *  \param txv tx to inspect
 *  \param pectx inspection context
 */
static void PrefilterTxFilename(DetectEngineThreadCtx *det_ctx, const void *pectx, Packet *p,
        Flow *f, void *txv, const uint64_t idx, const AppLayerTxData *txd, const uint8_t flags)
{
    SCEnter();

    if (!AppLayerParserHasFilesInDir(txd, flags))
        return;

    const PrefilterMpmFilename *ctx = (const PrefilterMpmFilename *)pectx;
    const MpmCtx *mpm_ctx = ctx->mpm_ctx;
    const int list_id = ctx->list_id;

    AppLayerGetFileState files = AppLayerParserGetTxFiles(f, txv, flags);
    FileContainer *ffc = files.fc;
    if (ffc != NULL) {
        int local_file_id = 0;
        for (File *file = ffc->head; file != NULL; file = file->next) {
            InspectionBuffer *buffer = FilenameGetDataCallback(
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

static void PrefilterMpmFilenameFree(void *ptr)
{
    SCFree(ptr);
}

static int PrefilterMpmFilenameRegister(DetectEngineCtx *de_ctx, SigGroupHead *sgh, MpmCtx *mpm_ctx,
        const DetectBufferMpmRegistry *mpm_reg, int list_id)
{
    PrefilterMpmFilename *pectx = SCCalloc(1, sizeof(*pectx));
    if (pectx == NULL)
        return -1;
    pectx->list_id = list_id;
    pectx->mpm_ctx = mpm_ctx;
    pectx->transforms = &mpm_reg->transforms;

    return PrefilterAppendTxEngine(de_ctx, sgh, PrefilterTxFilename,
            mpm_reg->app_v2.alproto, mpm_reg->app_v2.tx_min_progress,
            pectx, PrefilterMpmFilenameFree, mpm_reg->pname);
}

#ifdef UNITTESTS /* UNITTESTS */

/**
 * \test Test parser accepting valid rules and rejecting invalid rules
 */
static int DetectFilenameSignatureParseTest01(void)
{
    FAIL_IF_NOT(UTHParseSignature("alert http any any -> any any (flow:to_client; file.name; content:\"abc\"; sid:1;)", true));
    FAIL_IF_NOT(UTHParseSignature("alert http any any -> any any (flow:to_client; file.name; content:\"abc\"; nocase; sid:1;)", true));
    FAIL_IF_NOT(UTHParseSignature("alert http any any -> any any (flow:to_client; file.name; content:\"abc\"; endswith; sid:1;)", true));
    FAIL_IF_NOT(UTHParseSignature("alert http any any -> any any (flow:to_client; file.name; content:\"abc\"; startswith; sid:1;)", true));
    FAIL_IF_NOT(UTHParseSignature("alert http any any -> any any (flow:to_client; file.name; content:\"abc\"; startswith; endswith; sid:1;)", true));
    FAIL_IF_NOT(UTHParseSignature("alert http any any -> any any (flow:to_client; file.name; bsize:10; sid:1;)", true));

    FAIL_IF_NOT(UTHParseSignature("alert http any any -> any any (flow:to_client; file.name; content:\"abc\"; rawbytes; sid:1;)", false));
    FAIL_IF_NOT(UTHParseSignature("alert tcp any any -> any any (flow:to_client; file.name; sid:1;)", false));
    //FAIL_IF_NOT(UTHParseSignature("alert tls any any -> any any (flow:to_client; file.name; content:\"abc\"; sid:1;)", false));
    PASS;
}
/**
 * \brief this function registers unit tests for DetectFilename
 */
void DetectFilenameRegisterTests(void)
{
    UtRegisterTest("DetectFilenameSignatureParseTest01", DetectFilenameSignatureParseTest01);
}
#endif /* UNITTESTS */
