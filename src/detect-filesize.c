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
#include "app-layer-protos.h"
#include "app-layer-htp.h"
#include "util-unittest.h"
#include "util-unittest-helper.h"
#include "util-misc.h"

#include "detect.h"
#include "detect-parse.h"
#include "detect-engine.h"
#include "detect-engine-state.h"
#include "detect-engine-uint.h"
#include "detect-engine-build.h"

#include "detect-filesize.h"
#include "util-debug.h"
#include "util-byte.h"
#include "flow-util.h"
#include "stream-tcp.h"


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
#include "stream.h"
#include "stream-tcp-private.h"
#include "stream-tcp-reassemble.h"
#include "detect-engine-mpm.h"
#include "app-layer-parser.h"

/** \test   Test the Filesize keyword setup */
static int DetectFilesizeParseTest01(void)
{
    DetectU64Data *fsd = DetectU64Parse("10");
    FAIL_IF_NULL(fsd);
    FAIL_IF_NOT(fsd->arg1 == 10);
    FAIL_IF_NOT(fsd->mode == DETECT_UINT_EQ);
    DetectFilesizeFree(NULL, fsd);

    PASS;
}

/** \test   Test the Filesize keyword setup */
static int DetectFilesizeParseTest02(void)
{
    DetectU64Data *fsd = DetectU64Parse(" < 10  ");
    FAIL_IF_NULL(fsd);
    FAIL_IF_NOT(fsd->arg1 == 10);
    FAIL_IF_NOT(fsd->mode == DETECT_UINT_LT);
    DetectFilesizeFree(NULL, fsd);

    PASS;
}

/** \test   Test the Filesize keyword setup */
static int DetectFilesizeParseTest03(void)
{
    DetectU64Data *fsd = DetectU64Parse(" > 10 ");
    FAIL_IF_NULL(fsd);
    FAIL_IF_NOT(fsd->arg1 == 10);
    FAIL_IF_NOT(fsd->mode == DETECT_UINT_GT);
    DetectFilesizeFree(NULL, fsd);

    PASS;
}

/** \test   Test the Filesize keyword setup */
static int DetectFilesizeParseTest04(void)
{
    DetectU64Data *fsd = DetectU64Parse(" 5 <> 10 ");
    FAIL_IF_NULL(fsd);
    FAIL_IF_NOT(fsd->arg1 == 5);
    FAIL_IF_NOT(fsd->arg2 == 10);
    FAIL_IF_NOT(fsd->mode == DETECT_UINT_RA);
    DetectFilesizeFree(NULL, fsd);

    PASS;
}

/** \test   Test the Filesize keyword setup */
static int DetectFilesizeParseTest05(void)
{
    DetectU64Data *fsd = DetectU64Parse("5<>10");
    FAIL_IF_NULL(fsd);
    FAIL_IF_NOT(fsd->arg1 == 5);
    FAIL_IF_NOT(fsd->arg2 == 10);
    FAIL_IF_NOT(fsd->mode == DETECT_UINT_RA);
    DetectFilesizeFree(NULL, fsd);

    PASS;
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
    *de_ctx = NULL;

    *de_ctx = DetectEngineCtxInit();
    (*de_ctx)->flags |= DE_QUIET;
    FAIL_IF_NULL((*de_ctx));

    *sig = NULL;

    FAIL_IF(snprintf(fullstr, 1024,
                    "alert http any any -> any any (msg:\"Filesize "
                    "test\"; filesize:%s; sid:1;)",
                    str) >= 1024);

    Signature *s = DetectEngineAppendSig(*de_ctx, fullstr);
    FAIL_IF_NULL(s);

    *sig = (*de_ctx)->sig_list;

    *fsd = DetectU64Parse(str);

    PASS;
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
    FAIL_IF(res == 0);

    FAIL_IF_NULL(fsd);
    FAIL_IF_NOT(fsd->arg1 == 1);
    FAIL_IF_NOT(fsd->arg2 == 3);
    FAIL_IF_NOT(fsd->mode == DETECT_UINT_RA);

    DetectFilesizeFree(NULL, fsd);
    DetectEngineCtxFree(de_ctx);

    PASS;
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
