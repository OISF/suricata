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
#include "debug.h"
#include "decode.h"

#include "detect.h"
#include "detect-parse.h"
#include "detect-content.h"

#include "detect-engine.h"
#include "detect-engine-mpm.h"
#include "detect-engine-state.h"
#include "detect-engine-file.h"
#include "detect-engine-prefilter.h"
#include "detect-engine-content-inspection.h"

#include "flow.h"
#include "flow-var.h"
#include "flow-util.h"

#include "util-debug.h"
#include "util-spm-bm.h"
#include "util-unittest.h"
#include "util-unittest-helper.h"

#include "app-layer.h"

#include "stream-tcp.h"

#include "detect-filename.h"
#include "app-layer-parser.h"

typedef struct DetectFilenameData {
    uint8_t *name; /** name of the file to match */
    BmCtx *bm_ctx; /** BM context */
    uint16_t len;  /** name length */
    uint32_t flags;
} DetectFilenameData;

static int DetectFilenameMatch (DetectEngineThreadCtx *, Flow *,
        uint8_t, File *, const Signature *, const SigMatchCtx *);
static int DetectFilenameSetup (DetectEngineCtx *, Signature *, const char *);
static int DetectFilenameSetupSticky(DetectEngineCtx *de_ctx, Signature *s, const char *str);
#ifdef UNITTESTS
static void DetectFilenameRegisterTests(void);
#endif
static void DetectFilenameFree(DetectEngineCtx *, void *);
static int g_file_match_list_id = 0;
static int g_file_name_buffer_id = 0;

static int PrefilterMpmFilenameRegister(DetectEngineCtx *de_ctx,
        SigGroupHead *sgh, MpmCtx *mpm_ctx,
        const DetectBufferMpmRegistery *mpm_reg, int list_id);
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
    sigmatch_table[DETECT_FILENAME].FileMatch = DetectFilenameMatch;
    sigmatch_table[DETECT_FILENAME].Setup = DetectFilenameSetup;
    sigmatch_table[DETECT_FILENAME].Free  = DetectFilenameFree;
#ifdef UNITTESTS
    sigmatch_table[DETECT_FILENAME].RegisterTests = DetectFilenameRegisterTests;
#endif
    sigmatch_table[DETECT_FILENAME].flags = SIGMATCH_QUOTES_OPTIONAL|SIGMATCH_HANDLE_NEGATION;
    sigmatch_table[DETECT_FILENAME].alternative = DETECT_FILE_NAME;

    sigmatch_table[DETECT_FILE_NAME].name = "file.name";
    sigmatch_table[DETECT_FILE_NAME].desc = "sticky buffer to match on the file name";
    sigmatch_table[DETECT_FILE_NAME].url = "/rules/file-keywords.html#filename";
    sigmatch_table[DETECT_FILE_NAME].Setup = DetectFilenameSetupSticky;
    sigmatch_table[DETECT_FILE_NAME].flags = SIGMATCH_NOOPT|SIGMATCH_INFO_STICKY_BUFFER;

    DetectAppLayerInspectEngineRegister2("files", ALPROTO_HTTP1, SIG_FLAG_TOSERVER,
            HTP_REQUEST_BODY, DetectFileInspectGeneric, NULL);
    DetectAppLayerInspectEngineRegister2("files", ALPROTO_HTTP1, SIG_FLAG_TOCLIENT,
            HTP_RESPONSE_BODY, DetectFileInspectGeneric, NULL);

    DetectAppLayerInspectEngineRegister2(
            "files", ALPROTO_SMTP, SIG_FLAG_TOSERVER, 0, DetectFileInspectGeneric, NULL);

    DetectAppLayerInspectEngineRegister2(
            "files", ALPROTO_NFS, SIG_FLAG_TOSERVER, 0, DetectFileInspectGeneric, NULL);
    DetectAppLayerInspectEngineRegister2(
            "files", ALPROTO_NFS, SIG_FLAG_TOCLIENT, 0, DetectFileInspectGeneric, NULL);

    DetectAppLayerInspectEngineRegister2(
            "files", ALPROTO_FTPDATA, SIG_FLAG_TOSERVER, 0, DetectFileInspectGeneric, NULL);
    DetectAppLayerInspectEngineRegister2(
            "files", ALPROTO_FTPDATA, SIG_FLAG_TOCLIENT, 0, DetectFileInspectGeneric, NULL);

    DetectAppLayerInspectEngineRegister2(
            "files", ALPROTO_SMB, SIG_FLAG_TOSERVER, 0, DetectFileInspectGeneric, NULL);
    DetectAppLayerInspectEngineRegister2(
            "files", ALPROTO_SMB, SIG_FLAG_TOCLIENT, 0, DetectFileInspectGeneric, NULL);

    //this is used by filestore
    DetectAppLayerInspectEngineRegister2("files", ALPROTO_HTTP2, SIG_FLAG_TOSERVER,
            HTTP2StateDataClient, DetectFileInspectGeneric, NULL);
    DetectAppLayerInspectEngineRegister2("files", ALPROTO_HTTP2, SIG_FLAG_TOCLIENT,
            HTTP2StateDataServer, DetectFileInspectGeneric, NULL);

    g_file_match_list_id = DetectBufferTypeGetByName("files");

    AppProto protos_ts[] = { ALPROTO_HTTP1, ALPROTO_SMTP, ALPROTO_FTP, ALPROTO_FTPDATA, ALPROTO_SMB,
        ALPROTO_NFS, 0 };
    AppProto protos_tc[] = { ALPROTO_HTTP1, ALPROTO_FTP, ALPROTO_FTPDATA, ALPROTO_SMB, ALPROTO_NFS,
        0 };

    for (int i = 0; protos_ts[i] != 0; i++) {
        DetectAppLayerInspectEngineRegister2("file.name", protos_ts[i],
                SIG_FLAG_TOSERVER, 0,
                DetectEngineInspectFilename, NULL);

        DetectAppLayerMpmRegister2("file.name", SIG_FLAG_TOSERVER, 2,
                PrefilterMpmFilenameRegister, NULL, protos_ts[i],
                0);
    }
    for (int i = 0; protos_tc[i] != 0; i++) {
        DetectAppLayerInspectEngineRegister2("file.name", protos_tc[i],
                SIG_FLAG_TOCLIENT, 0,
                DetectEngineInspectFilename, NULL);

        DetectAppLayerMpmRegister2("file.name", SIG_FLAG_TOCLIENT, 2,
                PrefilterMpmFilenameRegister, NULL, protos_tc[i],
                0);
    }

    DetectBufferTypeSetDescriptionByName("file.name",
            "http user agent");

    g_file_name_buffer_id = DetectBufferTypeGetByName("file.name");
	SCLogDebug("registering filename rule option");
    return;
}

/**
 * \brief match the specified filename
 *
 * \param t thread local vars
 * \param det_ctx pattern matcher thread local data
 * \param f *LOCKED* flow
 * \param flags direction flags
 * \param file file being inspected
 * \param s signature being inspected
 * \param m sigmatch that we will cast into DetectFilenameData
 *
 * \retval 0 no match
 * \retval 1 match
 */
static int DetectFilenameMatch (DetectEngineThreadCtx *det_ctx,
        Flow *f, uint8_t flags, File *file, const Signature *s, const SigMatchCtx *m)
{
    SCEnter();
    int ret = 0;

    DetectFilenameData *filename = (DetectFilenameData *)m;

    if (file->name == NULL)
        SCReturnInt(0);

    if (BoyerMooreNocase(filename->name, filename->len, file->name,
                file->name_len, filename->bm_ctx) != NULL)
    {
#ifdef DEBUG
        if (SCLogDebugEnabled()) {
            char *name = SCMalloc(filename->len + 1);
            if (name != NULL) {
                memcpy(name, filename->name, filename->len);
                name[filename->len] = '\0';
                SCLogDebug("will look for filename %s", name);
                SCFree(name);
            }
        }
#endif

        if (!(filename->flags & DETECT_CONTENT_NEGATED)) {
            ret = 1;
        }
    }

    else if (filename->flags & DETECT_CONTENT_NEGATED) {
        SCLogDebug("negated match");
        ret = 1;
    }

    SCReturnInt(ret);
}

/**
 * \brief Parse the filename keyword
 *
 * \param de_ctx Pointer to the detection engine context
 * \param idstr Pointer to the user provided option
 *
 * \retval filename pointer to DetectFilenameData on success
 * \retval NULL on failure
 */
static DetectFilenameData *DetectFilenameParse (DetectEngineCtx *de_ctx, const char *str, bool negate)
{
    DetectFilenameData *filename = NULL;

    /* We have a correct filename option */
    filename = SCMalloc(sizeof(DetectFilenameData));
    if (unlikely(filename == NULL))
        goto error;

    memset(filename, 0x00, sizeof(DetectFilenameData));

    if (DetectContentDataParse ("filename", str, &filename->name, &filename->len) == -1) {
        goto error;
    }

    filename->bm_ctx = BoyerMooreNocaseCtxInit(filename->name, filename->len);
    if (filename->bm_ctx == NULL) {
        goto error;
    }

    if (negate) {
        filename->flags |= DETECT_CONTENT_NEGATED;
    }

    SCLogDebug("flags %02X", filename->flags);
    if (filename->flags & DETECT_CONTENT_NEGATED) {
        SCLogDebug("negated filename");
    }

#ifdef DEBUG
    if (SCLogDebugEnabled()) {
        char *name = SCMalloc(filename->len + 1);
        if (name != NULL) {
            memcpy(name, filename->name, filename->len);
            name[filename->len] = '\0';
            SCLogDebug("will look for filename %s", name);
            SCFree(name);
        }
    }
#endif

    return filename;

error:
    if (filename != NULL)
        DetectFilenameFree(de_ctx, filename);
    return NULL;
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
    DetectFilenameData *filename = NULL;
    SigMatch *sm = NULL;

    filename = DetectFilenameParse(de_ctx, str, s->init_data->negated);
    if (filename == NULL)
        goto error;

    /* Okay so far so good, lets get this into a SigMatch
     * and put it in the Signature. */
    sm = SigMatchAlloc();
    if (sm == NULL)
        goto error;

    sm->type = DETECT_FILENAME;
    sm->ctx = (void *)filename;

    SigMatchAppendSMToList(s, sm, g_file_match_list_id);

    s->file_flags |= (FILE_SIG_NEED_FILE|FILE_SIG_NEED_FILENAME);
    return 0;

error:
    if (filename != NULL)
        DetectFilenameFree(de_ctx, filename);
    if (sm != NULL)
        SCFree(sm);
    return -1;
}

/**
 * \brief this function will free memory associated with DetectFilenameData
 *
 * \param filename pointer to DetectFilenameData
 */
static void DetectFilenameFree(DetectEngineCtx *de_ctx, void *ptr)
{
    if (ptr != NULL) {
        DetectFilenameData *filename = (DetectFilenameData *)ptr;
        if (filename->bm_ctx != NULL) {
            BoyerMooreCtxDeInit(filename->bm_ctx);
        }
        if (filename->name != NULL)
            SCFree(filename->name);
        SCFree(filename);
    }
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
    if (DetectBufferSetActiveList(s, g_file_name_buffer_id) < 0)
        return -1;
    s->file_flags |= (FILE_SIG_NEED_FILE | FILE_SIG_NEED_FILENAME);
    return 0;
}

static InspectionBuffer *FilenameGetDataCallback(DetectEngineThreadCtx *det_ctx,
        const DetectEngineTransforms *transforms,
        Flow *f, uint8_t flow_flags, File *cur_file,
        int list_id, int local_file_id, bool first)
{
    SCEnter();

    InspectionBuffer *buffer = InspectionBufferMultipleForListGet(det_ctx, list_id, local_file_id);
    if (buffer == NULL)
        return NULL;
    if (!first && buffer->inspect != NULL)
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

    FileContainer *ffc = AppLayerParserGetFiles(f, flags);
    if (ffc == NULL) {
        return DETECT_ENGINE_INSPECT_SIG_NO_MATCH;
    }

    uint8_t r = DETECT_ENGINE_INSPECT_SIG_NO_MATCH;
    int local_file_id = 0;
    for (File *file = ffc->head; file != NULL; file = file->next) {
        if (file->txid != tx_id)
            continue;

        InspectionBuffer *buffer = FilenameGetDataCallback(det_ctx,
            transforms, f, flags, file, engine->sm_list, local_file_id, false);
        if (buffer == NULL)
            continue;

        det_ctx->buffer_offset = 0;
        det_ctx->discontinue_matching = 0;
        det_ctx->inspection_recursion_counter = 0;
        int match = DetectEngineContentInspection(de_ctx, det_ctx, s, engine->smd,
                                              NULL, f,
                                              (uint8_t *)buffer->inspect,
                                              buffer->inspect_len,
                                              buffer->inspect_offset, DETECT_CI_FLAGS_SINGLE,
                                              DETECT_ENGINE_CONTENT_INSPECTION_MODE_STATE);
        if (match == 1) {
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
static void PrefilterTxFilename(DetectEngineThreadCtx *det_ctx,
        const void *pectx,
        Packet *p, Flow *f, void *txv,
        const uint64_t idx, const uint8_t flags)
{
    SCEnter();

    const PrefilterMpmFilename *ctx = (const PrefilterMpmFilename *)pectx;
    const MpmCtx *mpm_ctx = ctx->mpm_ctx;
    const int list_id = ctx->list_id;

    FileContainer *ffc = AppLayerParserGetFiles(f, flags);
    if (ffc != NULL) {
        int local_file_id = 0;
        for (File *file = ffc->head; file != NULL; file = file->next) {
            if (file->txid != idx)
                continue;

            InspectionBuffer *buffer = FilenameGetDataCallback(det_ctx,
                    ctx->transforms, f, flags, file, list_id, local_file_id, true);
            if (buffer == NULL)
                continue;

            if (buffer->inspect_len >= mpm_ctx->minlen) {
                (void)mpm_table[mpm_ctx->mpm_type].Search(mpm_ctx,
                        &det_ctx->mtcu, &det_ctx->pmq,
                        buffer->inspect, buffer->inspect_len);
            }
            local_file_id++;
        }
    }
}

static void PrefilterMpmFilenameFree(void *ptr)
{
    SCFree(ptr);
}

static int PrefilterMpmFilenameRegister(DetectEngineCtx *de_ctx,
        SigGroupHead *sgh, MpmCtx *mpm_ctx,
        const DetectBufferMpmRegistery *mpm_reg, int list_id)
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
 * \test DetectFilenameTestParse01
 */
static int DetectFilenameTestParse01 (void)
{
    DetectFilenameData *dnd = DetectFilenameParse(NULL, "secret.pdf", false);
    if (dnd != NULL) {
        DetectFilenameFree(NULL, dnd);
        return 1;
    }
    return 0;
}

/**
 * \test DetectFilenameTestParse02
 */
static int DetectFilenameTestParse02 (void)
{
    int result = 0;

    DetectFilenameData *dnd = DetectFilenameParse(NULL, "backup.tar.gz", false);
    if (dnd != NULL) {
        if (dnd->len == 13 && memcmp(dnd->name, "backup.tar.gz", 13) == 0) {
            result = 1;
        }

        DetectFilenameFree(NULL, dnd);
        return result;
    }
    return 0;
}

/**
 * \test DetectFilenameTestParse03
 */
static int DetectFilenameTestParse03 (void)
{
    int result = 0;

    DetectFilenameData *dnd = DetectFilenameParse(NULL, "cmd.exe", false);
    if (dnd != NULL) {
        if (dnd->len == 7 && memcmp(dnd->name, "cmd.exe", 7) == 0) {
            result = 1;
        }

        DetectFilenameFree(NULL, dnd);
        return result;
    }
    return 0;
}


/**
 * \brief this function registers unit tests for DetectFilename
 */
void DetectFilenameRegisterTests(void)
{
    UtRegisterTest("DetectFilenameSignatureParseTest01", DetectFilenameSignatureParseTest01);

    UtRegisterTest("DetectFilenameTestParse01", DetectFilenameTestParse01);
    UtRegisterTest("DetectFilenameTestParse02", DetectFilenameTestParse02);
    UtRegisterTest("DetectFilenameTestParse03", DetectFilenameTestParse03);
}
#endif /* UNITTESTS */
