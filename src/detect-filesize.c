/* Copyright (C) 2007-2020 Open Information Security Foundation
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
 * Implements the filesize keyword
 */

#include "suricata-common.h"
#ifdef UNITTESTS
#include "detect-engine-build.h"
#include "util-unittest.h"
#endif

#include "detect-parse.h"
#include "detect-engine.h"
#include "detect-engine-uint.h"

#include "detect-filesize.h"

/*prototypes*/
static int DetectFilesizeMatch (DetectEngineThreadCtx *det_ctx, Flow *f,
        uint8_t flags, File *file, const Signature *s, const SigMatchCtx *m);
static int DetectFilesizeSetup (DetectEngineCtx *, Signature *, const char *);
static void DetectFilesizeFree (DetectEngineCtx *, void *);
#ifdef UNITTESTS
static void DetectFilesizeRegisterTests (void);
#endif
static int g_file_match_list_id = 0;

/**
 * \brief Registration function for filesize: keyword
 */

void DetectFilesizeRegister(void)
{
    sigmatch_table[DETECT_FILESIZE].name = "filesize";
    sigmatch_table[DETECT_FILESIZE].desc = "match on the size of the file as it is being transferred";
    sigmatch_table[DETECT_FILESIZE].url = "/rules/file-keywords.html#filesize";
    sigmatch_table[DETECT_FILESIZE].FileMatch = DetectFilesizeMatch;
    sigmatch_table[DETECT_FILESIZE].Setup = DetectFilesizeSetup;
    sigmatch_table[DETECT_FILESIZE].Free = DetectFilesizeFree;
#ifdef UNITTESTS
    sigmatch_table[DETECT_FILESIZE].RegisterTests = DetectFilesizeRegisterTests;
#endif

    g_file_match_list_id = DetectBufferTypeRegister("files");
}

/**
 * \brief   This function is used to match filesize rule option.
 *
 * \param t thread local vars
 * \param det_ctx pattern matcher thread local data
 * \param f *LOCKED* flow
 * \param flags direction flags
 * \param file file being inspected
 * \param s signature being inspected
 * \param m sigmatch that we will cast into DetectU64Data
 *
 * \retval 0 no match
 * \retval 1 match
 */
static int DetectFilesizeMatch (DetectEngineThreadCtx *det_ctx, Flow *f,
        uint8_t flags, File *file, const Signature *s, const SigMatchCtx *m)
{
    SCEnter();

    DetectU64Data *fsd = (DetectU64Data *)m;
    int ret = 0;
    uint64_t file_size = FileTrackedSize(file);

    SCLogDebug("file size %" PRIu64 ", check %" PRIu64, file_size, fsd->arg1);

    if (file->state == FILE_STATE_CLOSED) {
        return DetectU64Match(file_size, fsd);
        /* truncated, error: only see if what we have meets the GT condition */
    } else if (file->state > FILE_STATE_CLOSED) {
        if (fsd->mode == DETECT_UINT_GT || fsd->mode == DETECT_UINT_GTE) {
            ret = DetectU64Match(file_size, fsd);
        }
    }
    SCReturnInt(ret);
}

/**
 * \brief this function is used to parse filesize data into the current signature
 *
 * \param de_ctx pointer to the Detection Engine Context
 * \param s pointer to the Current Signature
 * \param str pointer to the user provided options
 *
 * \retval 0 on Success
 * \retval -1 on Failure
 */
static int DetectFilesizeSetup (DetectEngineCtx *de_ctx, Signature *s, const char *str)
{
    SCEnter();
    DetectU64Data *fsd = NULL;
    SigMatch *sm = NULL;

    fsd = DetectU64Parse(str);
    if (fsd == NULL)
        goto error;

    sm = SigMatchAlloc();
    if (sm == NULL)
        goto error;

    sm->type = DETECT_FILESIZE;
    sm->ctx = (SigMatchCtx *)fsd;

    SigMatchAppendSMToList(s, sm, g_file_match_list_id);

    s->file_flags |= (FILE_SIG_NEED_FILE|FILE_SIG_NEED_SIZE);
    SCReturnInt(0);

error:
    if (fsd != NULL)
        DetectFilesizeFree(de_ctx, fsd);
    if (sm != NULL)
        SCFree(sm);
    SCReturnInt(-1);
}

/**
 * \brief this function will free memory associated with DetectU64Data
 *
 * \param ptr pointer to DetectU64Data
 */
static void DetectFilesizeFree(DetectEngineCtx *de_ctx, void *ptr)
{
    rs_detect_u64_free(ptr);
}

#ifdef UNITTESTS
#include "detect-engine.h"

/** \test   Test the Filesize keyword setup */
static int DetectFilesizeParseTest01(void)
{
    int ret = 0;
    DetectU64Data *fsd = NULL;

    fsd = DetectU64Parse("10");
    if (fsd != NULL) {
        if (fsd->arg1 == 10 && fsd->mode == DETECT_UINT_EQ)
            ret = 1;

        DetectFilesizeFree(NULL, fsd);
    }
    return ret;
}

/** \test   Test the Filesize keyword setup */
static int DetectFilesizeParseTest02(void)
{
    int ret = 0;
    DetectU64Data *fsd = NULL;

    fsd = DetectU64Parse(" < 10  ");
    if (fsd != NULL) {
        if (fsd->arg1 == 10 && fsd->mode == DETECT_UINT_LT)
            ret = 1;

        DetectFilesizeFree(NULL, fsd);
    }
    return ret;
}

/** \test   Test the Filesize keyword setup */
static int DetectFilesizeParseTest03(void)
{
    int ret = 0;
    DetectU64Data *fsd = NULL;

    fsd = DetectU64Parse(" > 10 ");
    if (fsd != NULL) {
        if (fsd->arg1 == 10 && fsd->mode == DETECT_UINT_GT)
            ret = 1;

        DetectFilesizeFree(NULL, fsd);
    }
    return ret;
}

/** \test   Test the Filesize keyword setup */
static int DetectFilesizeParseTest04(void)
{
    int ret = 0;
    DetectU64Data *fsd = NULL;

    fsd = DetectU64Parse(" 5 <> 10 ");
    if (fsd != NULL) {
        if (fsd->arg1 == 5 && fsd->arg2 == 10 && fsd->mode == DETECT_UINT_RA)
            ret = 1;

        DetectFilesizeFree(NULL, fsd);
    }
    return ret;
}

/** \test   Test the Filesize keyword setup */
static int DetectFilesizeParseTest05(void)
{
    int ret = 0;
    DetectU64Data *fsd = NULL;

    fsd = DetectU64Parse("5<>10");
    if (fsd != NULL) {
        if (fsd->arg1 == 5 && fsd->arg2 == 10 && fsd->mode == DETECT_UINT_RA)
            ret = 1;

        DetectFilesizeFree(NULL, fsd);
    }
    return ret;
}

/**
 * \brief this function is used to initialize the detection engine context and
 *        setup the signature with passed values.
 *
 */

static int DetectFilesizeInitTest(
        DetectEngineCtx **de_ctx, Signature **sig, DetectU64Data **fsd, const char *str)
{
    char fullstr[1024];
    int result = 0;

    *de_ctx = NULL;
    *sig = NULL;

    if (snprintf(fullstr, 1024, "alert http any any -> any any (msg:\"Filesize "
                                "test\"; filesize:%s; sid:1;)", str) >= 1024) {
        goto end;
    }

    *de_ctx = DetectEngineCtxInit();
    if (*de_ctx == NULL) {
        goto end;
    }

    (*de_ctx)->flags |= DE_QUIET;

    (*de_ctx)->sig_list = SigInit(*de_ctx, fullstr);
    if ((*de_ctx)->sig_list == NULL) {
        goto end;
    }

    *sig = (*de_ctx)->sig_list;

    *fsd = DetectU64Parse(str);

    result = 1;

end:
    return result;
}

/**
 * \test DetectFilesizeSetpTest01 is a test for setting up an valid filesize values
 *       with valid "<>" operator and include spaces arround the given values.
 *       In the test the values are setup with initializing the detection engine
 *       context and setting up the signature itself.
 */

static int DetectFilesizeSetpTest01(void)
{

    DetectU64Data *fsd = NULL;
    uint8_t res = 0;
    Signature *sig = NULL;
    DetectEngineCtx *de_ctx = NULL;

    res = DetectFilesizeInitTest(&de_ctx, &sig, &fsd, "1 <> 3 ");
    if (res == 0) {
        goto end;
    }

    if(fsd == NULL)
        goto cleanup;

    if (fsd != NULL) {
        if (fsd->arg1 == 1 && fsd->arg2 == 3 && fsd->mode == DETECT_UINT_RA)
            res = 1;
    }

cleanup:
    if (fsd)
        DetectFilesizeFree(NULL, fsd);
    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
end:
    return res;
}

/**
 * \brief this function registers unit tests for DetectFilesize
 */
void DetectFilesizeRegisterTests(void)
{
    UtRegisterTest("DetectFilesizeParseTest01", DetectFilesizeParseTest01);
    UtRegisterTest("DetectFilesizeParseTest02", DetectFilesizeParseTest02);
    UtRegisterTest("DetectFilesizeParseTest03", DetectFilesizeParseTest03);
    UtRegisterTest("DetectFilesizeParseTest04", DetectFilesizeParseTest04);
    UtRegisterTest("DetectFilesizeParseTest05", DetectFilesizeParseTest05);
    UtRegisterTest("DetectFilesizeSetpTest01", DetectFilesizeSetpTest01);
}
#endif /* UNITTESTS */
