/* Copyright (C) 2007-2010 Open Information Security Foundation
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
 * \author Pablo Rincon <pablo.rincon.crespo@gmail.com>
 *
 */

#include "suricata-common.h"
#include "threads.h"
#include "debug.h"
#include "decode.h"

#include "detect.h"
#include "detect-parse.h"

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

#include "app-layer.h"

#include "stream-tcp.h"
#include "detect-fileext.h"

/**
 * \brief Regex for parsing the fileext string
 */
#define PARSE_REGEX  "^\\s*\"\\s*(.+)\\s*\"\\s*$"

static pcre *parse_regex;
static pcre_extra *parse_regex_study;

int DetectFileextMatch (ThreadVars *, DetectEngineThreadCtx *, Flow *, uint8_t, void *, Signature *, SigMatch *);
static int DetectFileextSetup (DetectEngineCtx *, Signature *, char *);
void DetectFileextRegisterTests(void);
void DetectFileextFree(void *);

/**
 * \brief Registration function for keyword: fileext
 */
void DetectFileextRegister(void) {
    sigmatch_table[DETECT_FILEEXT].name = "fileext";
    sigmatch_table[DETECT_FILEEXT].Match = NULL;
    sigmatch_table[DETECT_FILEEXT].AppLayerMatch = DetectFileextMatch;
    sigmatch_table[DETECT_FILEEXT].alproto = ALPROTO_HTTP;
    sigmatch_table[DETECT_FILEEXT].Setup = DetectFileextSetup;
    sigmatch_table[DETECT_FILEEXT].Free  = DetectFileextFree;
    sigmatch_table[DETECT_FILEEXT].RegisterTests = DetectFileextRegisterTests;

    const char *eb;
    int eo;
    int opts = 0;

	SCLogDebug("registering fileext rule option");

    parse_regex = pcre_compile(PARSE_REGEX, opts, &eb, &eo, NULL);
    if (parse_regex == NULL) {
        SCLogError(SC_ERR_PCRE_COMPILE, "Compile of \"%s\" failed at offset %" PRId32 ": %s",
                    PARSE_REGEX, eo, eb);
        goto error;
    }

    parse_regex_study = pcre_study(parse_regex, 0, &eb);
    if (eb != NULL) {
        SCLogError(SC_ERR_PCRE_STUDY, "pcre study failed: %s", eb);
        goto error;
    }
    return;

error:
    return;
}

/**
 * \brief match the specified file extension
 *
 * \param t pointer to thread vars
 * \param det_ctx pointer to the pattern matcher thread
 * \param p pointer to the current packet
 * \param m pointer to the sigmatch that we will cast into DetectFileextData
 *
 * \retval 0 no match
 * \retval 1 match
 */
int DetectFileextMatch (ThreadVars *t, DetectEngineThreadCtx *det_ctx, Flow *f, uint8_t flags, void *state, Signature *s, SigMatch *m)
{
    SCEnter();
    int ret = 0;

    DetectFileextData *fileext = m->ctx;

    SCMutexLock(&f->files_m);
    if (f->files != NULL && f->files->cnt > 0) {
        FlowFile *file = f->files->start;
        for (; file != NULL; file = file->next) {
            if (file != NULL && file->ext != NULL &&
                BoyerMooreNocase(fileext->ext, fileext->len, file->ext,
                file->ext_len, fileext->bm_ctx->bmGs, fileext->bm_ctx->bmBc) != NULL)
            {
                ret = 1;
                SCLogDebug("File ext %s found", file->ext);
                /* Stop searching */
                break;
            }
        }
    }
    SCMutexUnlock(&f->files_m);

    SCReturnInt(ret);
}

/**
 * \brief This function is used to parse fileet
 *
 * \param str Pointer to the fileext value string
 *
 * \retval pointer to DetectFileextData on success
 * \retval NULL on failure
 */
DetectFileextData *DetectFileextParse (char *str)
{
    DetectFileextData *fileext = NULL;
	#define MAX_SUBSTRINGS 30
    int ret = 0, res = 0;
    int ov[MAX_SUBSTRINGS];

    ret = pcre_exec(parse_regex, parse_regex_study, str, strlen(str), 0, 0,
                    ov, MAX_SUBSTRINGS);

    if (ret < 1 || ret > 3) {
        SCLogError(SC_ERR_PCRE_MATCH, "invalid fileext option");
        goto error;
    }

    if (ret > 1) {
        const char *str_ptr;
        res = pcre_get_substring((char *)str, ov, MAX_SUBSTRINGS, 1, &str_ptr);
        if (res < 0) {
            SCLogError(SC_ERR_PCRE_GET_SUBSTRING, "pcre_get_substring failed");
            goto error;
        }
        fileext = SCMalloc(sizeof(DetectFileextData));
        if (fileext == NULL)
            goto error;

        memset(fileext, 0x00, sizeof(DetectFileextData));

        /* Remove quotes if any and copy the filename */
        if (str_ptr[0] == '"') {
            fileext->ext = (uint8_t *)SCStrdup((char*)str_ptr + 1);
            fileext->ext[strlen(str_ptr - 1)] = '\0';
        } else {
            fileext->ext = (uint8_t *)SCStrdup((char*)str_ptr);
        }

        if (fileext->ext == NULL) {
            goto error;
        }
        fileext->len = strlen((char *) fileext->ext);
        fileext->bm_ctx = BoyerMooreCtxInit(fileext->ext, fileext->len);
        BoyerMooreCtxToNocase(fileext->bm_ctx, fileext->ext, fileext->len);

        SCLogDebug("will look for fileext %s", fileext->ext);
    }

    return fileext;

error:
    if (fileext != NULL)
        DetectFileextFree(fileext);
    return NULL;

}

/**
 * \brief this function is used to add the parsed "id" option
 * \brief into the current signature
 *
 * \param de_ctx pointer to the Detection Engine Context
 * \param s pointer to the Current Signature
 * \param idstr pointer to the user provided "id" option
 *
 * \retval 0 on Success
 * \retval -1 on Failure
 */
static int DetectFileextSetup (DetectEngineCtx *de_ctx, Signature *s, char *str)
{
    DetectFileextData *fileext= NULL;
    SigMatch *sm = NULL;

    fileext = DetectFileextParse(str);
    if (fileext == NULL)
        goto error;

    /* Okay so far so good, lets get this into a SigMatch
     * and put it in the Signature. */
    sm = SigMatchAlloc();
    if (sm == NULL)
        goto error;

    sm->type = DETECT_FILEEXT;
    sm->ctx = (void *)fileext;

    SigMatchAppendAppLayer(s, sm);

    if (s->alproto != ALPROTO_UNKNOWN && s->alproto != ALPROTO_HTTP) {
        SCLogError(SC_ERR_CONFLICTING_RULE_KEYWORDS, "rule contains conflicting keywords.");
        goto error;
    }

    AppLayerHtpNeedFileInspection();
    s->alproto = ALPROTO_HTTP;
    return 0;

error:
    if (fileext != NULL)
        DetectFileextFree(fileext);
    if (sm != NULL)
        SCFree(sm);
    return -1;

}

/**
 * \brief this function will free memory associated with DetectFileextData
 *
 * \param fileext pointer to DetectFileextData
 */
void DetectFileextFree(void *ptr) {
    DetectFileextData *fileext = (DetectFileextData *)ptr;
    BoyerMooreCtxDeInit(fileext->bm_ctx);
    SCFree(fileext);
}

#ifdef UNITTESTS /* UNITTESTS */

/**
 * \test DetectFileextTestParse01
 */
int DetectFileextTestParse01 (void) {
    return 0;
}

/**
 * \test DetectFileextTestParse02
 */
int DetectFileextTestParse02 (void) {
    return 0;
}

/**
 * \test DetectFileextTestParse03
 */
int DetectFileextTestParse03 (void) {
    return 1;
}


#include "stream-tcp-reassemble.h"

#endif /* UNITTESTS */

/**
 * \brief this function registers unit tests for DetectFileext
 */
void DetectFileextRegisterTests(void) {
#ifdef UNITTESTS /* UNITTESTS */
    UtRegisterTest("DetectFileextTestParse01", DetectFileextTestParse01, 1);
    UtRegisterTest("DetectFileextTestParse02", DetectFileextTestParse02, 1);
    UtRegisterTest("DetectFileextTestParse03", DetectFileextTestParse03, 1);
#endif /* UNITTESTS */
}
