/* Copyright (C) 2007-2012 Open Information Security Foundation
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

#include "detect.h"
#include "detect-parse.h"
#include "detect-engine.h"
#include "detect-engine-state.h"

#include "detect-filesize.h"
#include "util-debug.h"
#include "util-byte.h"
#include "flow-util.h"
#include "stream-tcp.h"

/**
 * \brief Regex for parsing our filesize
 */
#define PARSE_REGEX  "^(?:\\s*)(<|>)?(?:\\s*)([0-9]{1,23})(?:\\s*)(?:(<>)(?:\\s*)([0-9]{1,23}))?\\s*$"

static pcre *parse_regex;
static pcre_extra *parse_regex_study;

/*prototypes*/
static int DetectFilesizeMatch (ThreadVars *t, DetectEngineThreadCtx *det_ctx, Flow *f,
        uint8_t flags, File *file, const Signature *s, const SigMatchCtx *m);
static int DetectFilesizeSetup (DetectEngineCtx *, Signature *, const char *);
static void DetectFilesizeFree (void *);
static void DetectFilesizeRegisterTests (void);
static int g_file_match_list_id = 0;

/**
 * \brief Registration function for filesize: keyword
 */

void DetectFilesizeRegister(void)
{
    sigmatch_table[DETECT_FILESIZE].name = "filesize";
    sigmatch_table[DETECT_FILESIZE].desc = "match on the size of the file as it is being transferred";
    sigmatch_table[DETECT_FILESIZE].url = DOC_URL DOC_VERSION "/rules/file-keywords.html#filesize";
    sigmatch_table[DETECT_FILESIZE].FileMatch = DetectFilesizeMatch;
    sigmatch_table[DETECT_FILESIZE].Setup = DetectFilesizeSetup;
    sigmatch_table[DETECT_FILESIZE].Free = DetectFilesizeFree;
    sigmatch_table[DETECT_FILESIZE].RegisterTests = DetectFilesizeRegisterTests;

    DetectSetupParseRegexes(PARSE_REGEX, &parse_regex, &parse_regex_study);

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
 * \param m sigmatch that we will cast into DetectFilesizeData
 *
 * \retval 0 no match
 * \retval 1 match
 */
static int DetectFilesizeMatch (ThreadVars *t, DetectEngineThreadCtx *det_ctx, Flow *f,
        uint8_t flags, File *file, const Signature *s, const SigMatchCtx *m)
{
    SCEnter();

    DetectFilesizeData *fsd = (DetectFilesizeData *)m;
    int ret = 0;
    uint64_t file_size = FileTrackedSize(file);

    SCLogDebug("file size %"PRIu64", check %"PRIu64, file_size, fsd->size1);

    if (file->state == FILE_STATE_CLOSED) {
        switch (fsd->mode) {
            case DETECT_FILESIZE_EQ:
                if (file_size == fsd->size1)
                    ret = 1;
                break;
            case DETECT_FILESIZE_LT:
                if (file_size < fsd->size1)
                    ret = 1;
                break;
            case DETECT_FILESIZE_GT:
                if (file_size > fsd->size1)
                    ret = 1;
                break;
            case DETECT_FILESIZE_RA:
                if (file_size > fsd->size1 && file_size < fsd->size2)
                    ret = 1;
                break;
        }
    /* truncated, error: only see if what we have meets the GT condition */
    } else if (file->state > FILE_STATE_CLOSED) {
        if (fsd->mode == DETECT_FILESIZE_GT && file_size > fsd->size1)
            ret = 1;
    }
    SCReturnInt(ret);
}

/**
 * \brief parse filesize options
 *
 * \param str pointer to the user provided filesize
 *
 * \retval fsd pointer to DetectFilesizeData on success
 * \retval NULL on failure
 */
static DetectFilesizeData *DetectFilesizeParse (const char *str)
{

    DetectFilesizeData *fsd = NULL;
    char *arg1 = NULL;
    char *arg2 = NULL;
    char *arg3 = NULL;
    char *arg4 = NULL;
#define MAX_SUBSTRINGS 30
    int ret = 0, res = 0;
    int ov[MAX_SUBSTRINGS];

    ret = pcre_exec(parse_regex, parse_regex_study, str, strlen(str),
                    0, 0, ov, MAX_SUBSTRINGS);
    if (ret < 3 || ret > 5) {
        SCLogError(SC_ERR_PCRE_PARSE, "filesize option pcre parse error: \"%s\"", str);
        goto error;
    }
    const char *str_ptr;

    SCLogDebug("ret %d", ret);

    res = pcre_get_substring((char *)str, ov, MAX_SUBSTRINGS, 1, &str_ptr);
    if (res < 0) {
        SCLogError(SC_ERR_PCRE_GET_SUBSTRING, "pcre_get_substring failed");
        goto error;
    }
    arg1 = (char *) str_ptr;
    SCLogDebug("Arg1 \"%s\"", arg1);

    res = pcre_get_substring((char *)str, ov, MAX_SUBSTRINGS, 2, &str_ptr);
    if (res < 0) {
        SCLogError(SC_ERR_PCRE_GET_SUBSTRING, "pcre_get_substring failed");
        goto error;
    }
    arg2 = (char *) str_ptr;
    SCLogDebug("Arg2 \"%s\"", arg2);

    if (ret > 3) {
        res = pcre_get_substring((char *)str, ov, MAX_SUBSTRINGS, 3, &str_ptr);
        if (res < 0) {
            SCLogError(SC_ERR_PCRE_GET_SUBSTRING, "pcre_get_substring failed");
            goto error;
        }
        arg3 = (char *) str_ptr;
        SCLogDebug("Arg3 \"%s\"", arg3);

        if (ret > 4) {
            res = pcre_get_substring((char *)str, ov, MAX_SUBSTRINGS, 4, &str_ptr);
            if (res < 0) {
                SCLogError(SC_ERR_PCRE_GET_SUBSTRING, "pcre_get_substring failed");
                goto error;
            }
            arg4 = (char *) str_ptr;
            SCLogDebug("Arg4 \"%s\"", arg4);
        }
    }

    fsd = SCMalloc(sizeof (DetectFilesizeData));
    if (unlikely(fsd == NULL))
    goto error;
    memset(fsd, 0, sizeof(DetectFilesizeData));

    if (arg1[0] == '<')
        fsd->mode = DETECT_FILESIZE_LT;
    else if (arg1[0] == '>')
        fsd->mode = DETECT_FILESIZE_GT;
    else
        fsd->mode = DETECT_FILESIZE_EQ;

    if (arg3 != NULL && strcmp("<>", arg3) == 0) {
        if (strlen(arg1) != 0) {
            SCLogError(SC_ERR_INVALID_ARGUMENT,"Range specified but mode also set");
            goto error;
        }
        fsd->mode = DETECT_FILESIZE_RA;
    }

    /** set the first value */
    if (ByteExtractStringUint64(&fsd->size1,10,strlen(arg2),arg2) <= 0){
        SCLogError(SC_ERR_INVALID_ARGUMENT,"Invalid size :\"%s\"",arg2);
        goto error;
    }

    /** set the second value if specified */
    if (arg4 != NULL && strlen(arg4) > 0) {
        if (fsd->mode != DETECT_FILESIZE_RA) {
            SCLogError(SC_ERR_INVALID_ARGUMENT,"Multiple filesize values specified"
                                           " but mode is not range");
            goto error;
        }

        if(ByteExtractStringUint64(&fsd->size2,10,strlen(arg4),arg4) <= 0)
        {
            SCLogError(SC_ERR_INVALID_ARGUMENT,"Invalid size :\"%s\"",arg4);
            goto error;
        }

        if (fsd->size2 <= fsd->size1){
            SCLogError(SC_ERR_INVALID_ARGUMENT,"filesize2:%"PRIu64" <= filesize:"
                        "%"PRIu64"",fsd->size2,fsd->size1);
            goto error;
        }
    }

    pcre_free_substring(arg1);
    pcre_free_substring(arg2);
    if (arg3 != NULL)
        pcre_free_substring(arg3);
    if (arg4 != NULL)
        pcre_free_substring(arg4);
    return fsd;

error:
    if (fsd)
        SCFree(fsd);
    if (arg1 != NULL)
        SCFree(arg1);
    if (arg2 != NULL)
        SCFree(arg2);
    if (arg3 != NULL)
        SCFree(arg3);
    if (arg4 != NULL)
        SCFree(arg4);
    return NULL;
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
    DetectFilesizeData *fsd = NULL;
    SigMatch *sm = NULL;

    fsd = DetectFilesizeParse(str);
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
        DetectFilesizeFree(fsd);
    if (sm != NULL)
        SCFree(sm);
    SCReturnInt(-1);
}

/**
 * \brief this function will free memory associated with DetectFilesizeData
 *
 * \param ptr pointer to DetectFilesizeData
 */
static void DetectFilesizeFree(void *ptr)
{
    DetectFilesizeData *fsd = (DetectFilesizeData *)ptr;
    SCFree(fsd);
}

#ifdef UNITTESTS
#include "stream.h"
#include "stream-tcp-private.h"
#include "stream-tcp-reassemble.h"
#include "detect-engine.h"
#include "detect-engine-mpm.h"
#include "app-layer-parser.h"

/** \test   Test the Filesize keyword setup */
static int DetectFilesizeParseTest01(void)
{
    int ret = 0;
    DetectFilesizeData *fsd = NULL;

    fsd = DetectFilesizeParse("10");
    if (fsd != NULL) {
        if (fsd->size1 == 10 && fsd->mode == DETECT_FILESIZE_EQ)
            ret = 1;

        DetectFilesizeFree(fsd);
    }
    return ret;
}

/** \test   Test the Filesize keyword setup */
static int DetectFilesizeParseTest02(void)
{
    int ret = 0;
    DetectFilesizeData *fsd = NULL;

    fsd = DetectFilesizeParse(" < 10  ");
    if (fsd != NULL) {
        if (fsd->size1 == 10 && fsd->mode == DETECT_FILESIZE_LT)
            ret = 1;

        DetectFilesizeFree(fsd);
    }
    return ret;
}

/** \test   Test the Filesize keyword setup */
static int DetectFilesizeParseTest03(void)
{
    int ret = 0;
    DetectFilesizeData *fsd = NULL;

    fsd = DetectFilesizeParse(" > 10 ");
    if (fsd != NULL) {
        if (fsd->size1 == 10 && fsd->mode == DETECT_FILESIZE_GT)
            ret = 1;

        DetectFilesizeFree(fsd);
    }
    return ret;
}

/** \test   Test the Filesize keyword setup */
static int DetectFilesizeParseTest04(void)
{
    int ret = 0;
    DetectFilesizeData *fsd = NULL;

    fsd = DetectFilesizeParse(" 5 <> 10 ");
    if (fsd != NULL) {
        if (fsd->size1 == 5 && fsd->size2 == 10 &&
            fsd->mode == DETECT_FILESIZE_RA)
            ret = 1;

        DetectFilesizeFree(fsd);
    }
    return ret;
}

/** \test   Test the Filesize keyword setup */
static int DetectFilesizeParseTest05(void)
{
    int ret = 0;
    DetectFilesizeData *fsd = NULL;

    fsd = DetectFilesizeParse("5<>10");
    if (fsd != NULL) {
        if (fsd->size1 == 5 && fsd->size2 == 10 &&
            fsd->mode == DETECT_FILESIZE_RA)
            ret = 1;

        DetectFilesizeFree(fsd);
    }
    return ret;
}

/**
 * \brief this function is used to initialize the detection engine context and
 *        setup the signature with passed values.
 *
 */

static int DetectFilesizeInitTest(DetectEngineCtx **de_ctx, Signature **sig,
                                DetectFilesizeData **fsd, const char *str)
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

    *fsd = DetectFilesizeParse(str);

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

    DetectFilesizeData *fsd = NULL;
    uint8_t res = 0;
    Signature *sig = NULL;
    DetectEngineCtx *de_ctx = NULL;

    res = DetectFilesizeInitTest(&de_ctx, &sig, &fsd, "1 <> 2 ");
    if (res == 0) {
        goto end;
    }

    if(fsd == NULL)
        goto cleanup;

    if (fsd != NULL) {
        if (fsd->size1 == 1 && fsd->size2 == 2 &&
                fsd->mode == DETECT_FILESIZE_RA)
            res = 1;
    }

cleanup:
    if (fsd)
        SCFree(fsd);
    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
end:
    return res;
}

#endif /* UNITTESTS */

/**
 * \brief this function registers unit tests for DetectFilesize
 */
void DetectFilesizeRegisterTests(void)
{
#ifdef UNITTESTS
    UtRegisterTest("DetectFilesizeParseTest01", DetectFilesizeParseTest01);
    UtRegisterTest("DetectFilesizeParseTest02", DetectFilesizeParseTest02);
    UtRegisterTest("DetectFilesizeParseTest03", DetectFilesizeParseTest03);
    UtRegisterTest("DetectFilesizeParseTest04", DetectFilesizeParseTest04);
    UtRegisterTest("DetectFilesizeParseTest05", DetectFilesizeParseTest05);
    UtRegisterTest("DetectFilesizeSetpTest01", DetectFilesizeSetpTest01);
#endif /* UNITTESTS */
}
