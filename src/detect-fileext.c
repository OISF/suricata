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

#include "flow.h"
#include "flow-var.h"
#include "flow-util.h"

#include "util-debug.h"
#include "util-unittest.h"
#include "util-unittest-helper.h"
#include "util-spm-bm.h"
#include "util-print.h"
#include "util-memcmp.h"

#include "app-layer.h"

#include "stream-tcp.h"
#include "detect-fileext.h"

static int DetectFileextMatch (DetectEngineThreadCtx *, Flow *,
        uint8_t, File *, const Signature *, const SigMatchCtx *);
static int DetectFileextSetup (DetectEngineCtx *, Signature *, const char *);
#ifdef UNITTESTS
static void DetectFileextRegisterTests(void);
#endif
static void DetectFileextFree(DetectEngineCtx *, void *);
static int g_file_match_list_id = 0;

/**
 * \brief Registration function for keyword: fileext
 */
void DetectFileextRegister(void)
{
    sigmatch_table[DETECT_FILEEXT].name = "fileext";
    sigmatch_table[DETECT_FILEEXT].desc = "match on the extension of a file name";
    sigmatch_table[DETECT_FILEEXT].url = "/rules/file-keywords.html#fileext";
    sigmatch_table[DETECT_FILEEXT].FileMatch = DetectFileextMatch;
    sigmatch_table[DETECT_FILEEXT].Setup = DetectFileextSetup;
    sigmatch_table[DETECT_FILEEXT].Free  = DetectFileextFree;
#ifdef UNITTESTS
    sigmatch_table[DETECT_FILEEXT].RegisterTests = DetectFileextRegisterTests;
#endif
    sigmatch_table[DETECT_FILEEXT].flags = SIGMATCH_QUOTES_OPTIONAL|SIGMATCH_HANDLE_NEGATION;
    sigmatch_table[DETECT_FILEEXT].alternative = DETECT_FILE_NAME;

    g_file_match_list_id = DetectBufferTypeRegister("files");

	SCLogDebug("registering fileext rule option");
    return;
}

/**
 * \brief match the specified file extension
 *
 * \param t thread local vars
 * \param det_ctx pattern matcher thread local data
 * \param f *LOCKED* flow
 * \param flags direction flags
 * \param file file being inspected
 * \param s signature being inspected
 * \param m sigmatch that we will cast into DetectFileextData
 *
 * \retval 0 no match
 * \retval 1 match
 */
static int DetectFileextMatch (DetectEngineThreadCtx *det_ctx,
        Flow *f, uint8_t flags, File *file, const Signature *s, const SigMatchCtx *m)
{
    SCEnter();
    int ret = 0;

    DetectFileextData *fileext = (DetectFileextData *)m;

    if (file->name == NULL)
        SCReturnInt(0);

    if (file->name_len <= fileext->len)
        SCReturnInt(0);

    int offset = file->name_len - fileext->len;

    /* fileext->ext is already in lowercase, as SCMemcmpLowercase requires */
    if (file->name[offset - 1] == '.' &&
        SCMemcmpLowercase(fileext->ext, file->name + offset, fileext->len) == 0)
    {
        if (!(fileext->flags & DETECT_CONTENT_NEGATED)) {
            ret = 1;
            SCLogDebug("File ext found");
        }
    } else if (fileext->flags & DETECT_CONTENT_NEGATED) {
        SCLogDebug("negated match");
        ret = 1;
    }

    SCReturnInt(ret);
}

/**
 * \brief This function is used to parse fileet
 *
 * \param de_ctx Pointer to the detection engine context
 * \param str Pointer to the fileext value string
 *
 * \retval pointer to DetectFileextData on success
 * \retval NULL on failure
 */
static DetectFileextData *DetectFileextParse (DetectEngineCtx *de_ctx, const char *str, bool negate)
{
    DetectFileextData *fileext = NULL;

    /* We have a correct filename option */
    fileext = SCMalloc(sizeof(DetectFileextData));
    if (unlikely(fileext == NULL))
        goto error;

    memset(fileext, 0x00, sizeof(DetectFileextData));

    if (DetectContentDataParse("fileext", str, &fileext->ext, &fileext->len) == -1) {
        goto error;
    }
    uint16_t u;
    for (u = 0; u < fileext->len; u++)
        fileext->ext[u] = u8_tolower(fileext->ext[u]);

    if (negate) {
        fileext->flags |= DETECT_CONTENT_NEGATED;
    }

    SCLogDebug("flags %02X", fileext->flags);
    if (fileext->flags & DETECT_CONTENT_NEGATED) {
        SCLogDebug("negated fileext");
    }

#ifdef DEBUG
    if (SCLogDebugEnabled()) {
        char *ext = SCMalloc(fileext->len + 1);
        if (ext != NULL) {
            memcpy(ext, fileext->ext, fileext->len);
            ext[fileext->len] = '\0';
            SCLogDebug("will look for fileext %s", ext);
            SCFree(ext);
        }
    }
#endif

    return fileext;

error:
    if (fileext != NULL)
        DetectFileextFree(de_ctx, fileext);
    return NULL;

}

/**
 * \brief this function is used to add the parsed "id" option
 *        into the current signature
 *
 * \param de_ctx pointer to the Detection Engine Context
 * \param s pointer to the Current Signature
 * \param idstr pointer to the user provided "id" option
 *
 * \retval 0 on Success
 * \retval -1 on Failure
 */
static int DetectFileextSetup (DetectEngineCtx *de_ctx, Signature *s, const char *str)
{
    DetectFileextData *fileext= NULL;
    SigMatch *sm = NULL;

    fileext = DetectFileextParse(de_ctx, str, s->init_data->negated);
    if (fileext == NULL)
        goto error;

    /* Okay so far so good, lets get this into a SigMatch
     * and put it in the Signature. */
    sm = SigMatchAlloc();
    if (sm == NULL)
        goto error;

    sm->type = DETECT_FILEEXT;
    sm->ctx = (void *)fileext;

    SigMatchAppendSMToList(s, sm, g_file_match_list_id);

    s->file_flags |= (FILE_SIG_NEED_FILE|FILE_SIG_NEED_FILENAME);
    return 0;

error:
    if (fileext != NULL)
        DetectFileextFree(de_ctx, fileext);
    if (sm != NULL)
        SCFree(sm);
    return -1;

}

/**
 * \brief this function will free memory associated with DetectFileextData
 *
 * \param fileext pointer to DetectFileextData
 */
static void DetectFileextFree(DetectEngineCtx *de_ctx, void *ptr)
{
    if (ptr != NULL) {
        DetectFileextData *fileext = (DetectFileextData *)ptr;
        if (fileext->ext != NULL)
            SCFree(fileext->ext);
        SCFree(fileext);
    }
}

#ifdef UNITTESTS /* UNITTESTS */

/**
 * \test DetectFileextTestParse01
 */
static int DetectFileextTestParse01 (void)
{
    DetectFileextData *dfd = DetectFileextParse(NULL, "doc", false);
    if (dfd != NULL) {
        DetectFileextFree(NULL, dfd);
        return 1;
    }
    return 0;
}

/**
 * \test DetectFileextTestParse02
 */
static int DetectFileextTestParse02 (void)
{
    int result = 0;

    DetectFileextData *dfd = DetectFileextParse(NULL, "tar.gz", false);
    if (dfd != NULL) {
        if (dfd->len == 6 && memcmp(dfd->ext, "tar.gz", 6) == 0) {
            result = 1;
        }

        DetectFileextFree(NULL, dfd);
        return result;
    }
    return 0;
}

/**
 * \test DetectFileextTestParse03
 */
static int DetectFileextTestParse03 (void)
{
    int result = 0;

    DetectFileextData *dfd = DetectFileextParse(NULL, "pdf", false);
    if (dfd != NULL) {
        if (dfd->len == 3 && memcmp(dfd->ext, "pdf", 3) == 0) {
            result = 1;
        }

        DetectFileextFree(NULL, dfd);
        return result;
    }
    return 0;
}

/**
 * \brief this function registers unit tests for DetectFileext
 */
void DetectFileextRegisterTests(void)
{
    UtRegisterTest("DetectFileextTestParse01", DetectFileextTestParse01);
    UtRegisterTest("DetectFileextTestParse02", DetectFileextTestParse02);
    UtRegisterTest("DetectFileextTestParse03", DetectFileextTestParse03);
}
#endif /* UNITTESTS */
