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
 * \author Breno Silva <breno.silva@gmail.com>
 * \author Anoop Saldanha <anoopsaldanha@gmail.com>
 *
 * Implements the reference keyword support
 */

#include "suricata-common.h"
#include "suricata.h"
#include "detect.h"
#include "detect-parse.h"
#include "detect-engine.h"
#include "detect-engine-mpm.h"

#include "decode.h"
#include "flow-var.h"
#include "decode-events.h"
#include "stream-tcp.h"

#include "util-reference-config.h"
#include "detect-reference.h"

#include "util-unittest.h"
#include "util-byte.h"
#include "util-debug.h"

#define PARSE_REGEX "^\\s*([A-Za-z0-9]+)\\s*,\"?\\s*\"?\\s*([a-zA-Z0-9\\-_\\.\\/\\?\\=]+)\"?\\s*\"?"

static pcre *parse_regex;
static pcre_extra *parse_regex_study;

static int DetectReferenceSetup(DetectEngineCtx *, Signature *s, char *str);

/**
 * \brief Registration function for the reference: keyword
 */
void DetectReferenceRegister(void)
{
    sigmatch_table[DETECT_REFERENCE].name = "reference";
    sigmatch_table[DETECT_REFERENCE].desc = "direct to places where information about the rule can be found";
    sigmatch_table[DETECT_REFERENCE].url = "https://redmine.openinfosecfoundation.org/projects/suricata/wiki/Meta-settings#Reference";
    sigmatch_table[DETECT_REFERENCE].Match = NULL;
    sigmatch_table[DETECT_REFERENCE].Setup = DetectReferenceSetup;
    sigmatch_table[DETECT_REFERENCE].Free  = NULL;
    sigmatch_table[DETECT_REFERENCE].RegisterTests = ReferenceRegisterTests;

    const char *eb;
    int opts = 0;
    int eo;

    opts |= PCRE_CASELESS;

    parse_regex = pcre_compile(PARSE_REGEX, opts, &eb, &eo, NULL);
    if (parse_regex == NULL) {
        SCLogError(SC_ERR_PCRE_COMPILE, "pcre compile of \"%s\" failed at "
                   "offset %" PRId32 ": %s", PARSE_REGEX, eo, eb);
        goto error;
    }

    parse_regex_study = pcre_study(parse_regex, 0, &eb);
    if (eb != NULL) {
        SCLogError(SC_ERR_PCRE_STUDY, "pcre study failed: %s", eb);
        goto error;
    }

error:
    return;
}

/**
 *  \brief Free a Reference object
 */
void DetectReferenceFree(DetectReference *ref)
{
    SCEnter();

    if (ref->reference != NULL) {
        SCFree(ref->reference);
    }
    SCFree(ref);

    SCReturn;
}

/**
 * \internal
 * \brief This function is used to parse reference options passed via reference: keyword
 *
 * \param rawstr Pointer to the user provided reference options.
 *
 * \retval ref  Pointer to signature reference on success.
 * \retval NULL On failure.
 */
static DetectReference *DetectReferenceParse(char *rawstr, DetectEngineCtx *de_ctx)
{
    SCEnter();

    DetectReference *ref = NULL;
#define MAX_SUBSTRINGS 30
    int ret = 0, res = 0;
    int ov[MAX_SUBSTRINGS];
    char key[64] = "";
    char content[1024] = "";

    ret = pcre_exec(parse_regex, parse_regex_study, rawstr, strlen(rawstr),
                    0, 0, ov, MAX_SUBSTRINGS);
    if (ret < 2) {
        SCLogError(SC_ERR_INVALID_SIGNATURE, "Unable to parse \"reference\" "
                   "keyword argument - \"%s\".   Invalid argument.", rawstr);
        goto error;
    }

    ref = SCMalloc(sizeof(DetectReference));
    if (unlikely(ref == NULL)) {
        goto error;
    }
    memset(ref, 0, sizeof(DetectReference));

    res = pcre_copy_substring((char *)rawstr, ov, MAX_SUBSTRINGS, 1, key, sizeof(key));
    if (res < 0) {
        SCLogError(SC_ERR_PCRE_GET_SUBSTRING, "pcre_copy_substring failed");
        goto error;
    }

    res = pcre_copy_substring((char *)rawstr, ov, MAX_SUBSTRINGS, 2, content, sizeof(content));
    if (res < 0) {
        SCLogError(SC_ERR_PCRE_GET_SUBSTRING, "pcre_get_substring failed");
        goto error;
    }

    if (strlen(key) == 0 || strlen(content) == 0)
        goto error;

    SCRConfReference *lookup_ref_conf = SCRConfGetReference(key, de_ctx);
    if (lookup_ref_conf != NULL) {
        ref->key = lookup_ref_conf->url;
    } else {
        SCLogError(SC_ERR_REFERENCE_UNKNOWN, "unknown reference key \"%s\". "
                   "Supported keys are defined in reference.config file.  Please "
                   "have a look at the conf param \"reference-config-file\"", key);
        goto error;
    }

    /* make a copy so we can free pcre's substring */
    ref->reference = SCStrdup((char *)content);
    if (ref->reference == NULL) {
        SCLogError(SC_ERR_MEM_ALLOC, "strdup failed: %s", strerror(errno));
        goto error;
    }

    /* free the substrings */
    SCReturnPtr(ref, "Reference");

error:
    if (ref != NULL)
        DetectReferenceFree(ref);

    SCReturnPtr(NULL, "Reference");
}

/**
 * \internal
 * \brief Used to add the parsed reference into the current signature.
 *
 * \param de_ctx Pointer to the Detection Engine Context.
 * \param s      Pointer to the Current Signature.
 * \param m      Pointer to the Current SigMatch.
 * \param rawstr Pointer to the user provided reference options.
 *
 * \retval  0 On Success.
 * \retval -1 On Failure.
 */
static int DetectReferenceSetup(DetectEngineCtx *de_ctx, Signature *s,
                                char *rawstr)
{
    SCEnter();

    DetectReference *ref = NULL;
    DetectReference *sig_refs = NULL;

    ref = DetectReferenceParse(rawstr, de_ctx);
    if (ref == NULL)
        goto error;

    SCLogDebug("ref %s %s", ref->key, ref->reference);

    if (s->references == NULL)  {
        s->references = ref;
    } else {
        sig_refs = s->references;
        while (sig_refs->next != NULL) {
            sig_refs = sig_refs->next;
        }
        sig_refs->next = ref;
        ref->next = NULL;
    }

    SCReturnInt(0);

error:
    SCReturnInt(-1);
}

/***************************************Unittests******************************/

#ifdef UNITTESTS

/**
 * \test one valid reference.
 *
 *  \retval 1 on succces.
 *  \retval 0 on failure.
 */
static int DetectReferenceParseTest01(void)
{
    int result = 0;
    Signature *s = NULL;
    DetectReference *ref = NULL;

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        goto cleanup;
    }
    de_ctx->flags |= DE_QUIET;

    FILE *fd = SCRConfGenerateValidDummyReferenceConfigFD01();
    SCRConfLoadReferenceConfigFile(de_ctx, fd);

    s = de_ctx->sig_list = SigInit(de_ctx, "alert icmp any any -> any any "
                                   "(msg:\"One reference\"; reference:one,001-2010; sid:2;)");
    if (s == NULL) {
        goto cleanup;
    }

    if (s->references == NULL)  {
        goto cleanup;
    }

    ref = s->references;
    if (strcmp(ref->key, "http://www.one.com") != 0 ||
        strcmp(ref->reference, "001-2010") != 0) {
        goto cleanup;
    }

    result = 1;

cleanup:
    if (de_ctx != NULL) {
        DetectEngineCtxFree(de_ctx);
    }
    return result;

}

/**
 * \test for two valid references.
 *
 *  \retval 1 on succces.
 *  \retval 0 on failure.
 */
static int DetectReferenceParseTest02(void)
{
    int result = 0;
    Signature *s = NULL;

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        goto cleanup;
    }
    de_ctx->flags |= DE_QUIET;

    FILE *fd = SCRConfGenerateValidDummyReferenceConfigFD01();
    SCRConfLoadReferenceConfigFile(de_ctx, fd);

    s = de_ctx->sig_list = SigInit(de_ctx, "alert icmp any any -> any any "
                                   "(msg:\"Two references\"; "
                                   "reference:one,openinfosecdoundation.txt; "
                                   "reference:two,001-2010; sid:2;)");
    if (s == NULL) {
        printf("sig parse failed: ");
        goto cleanup;
    }

    if (s->references == NULL || s->references->next == NULL)  {
        printf("no ref or not enough refs: ");
        goto cleanup;
    }

    if (strcmp(s->references->key, "http://www.one.com") != 0 ||
        strcmp(s->references->reference, "openinfosecdoundation.txt") != 0) {
        printf("first ref failed: ");
        goto cleanup;
    }

    if (strcmp(s->references->next->key, "http://www.two.com") != 0 ||
        strcmp(s->references->next->reference, "001-2010") != 0) {
        printf("second ref failed: ");
        goto cleanup;
    }

    result = 1;

cleanup:
    if (de_ctx != NULL) {
        DetectEngineCtxFree(de_ctx);
    }
    return result;
}

/**
 * \test parsing: invalid reference.
 *
 *  \retval 1 on succces.
 *  \retval 0 on failure.
 */
static int DetectReferenceParseTest03(void)
{
    int result = 0;
    Signature *s = NULL;
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        goto cleanup;
    }
    de_ctx->flags |= DE_QUIET;

    FILE *fd =SCRConfGenerateValidDummyReferenceConfigFD01();
    SCRConfLoadReferenceConfigFile(de_ctx, fd);

    s = de_ctx->sig_list = SigInit(de_ctx, "alert icmp any any -> any any "
                                   "(msg:\"invalid ref\"; "
                                   "reference:unknownkey,001-2010; sid:2;)");
    if (s != NULL) {
        printf("sig parsed even though it's invalid: ");
        goto cleanup;
    }

    result = 1;

cleanup:
    if (de_ctx != NULL) {
        DetectEngineCtxFree(de_ctx);
    }
    return result;
}

#endif /* UNITTESTS */

void ReferenceRegisterTests(void)
{
#ifdef UNITTESTS
    UtRegisterTest("DetectReferenceParseTest01", DetectReferenceParseTest01, 1);
    UtRegisterTest("DetectReferenceParseTest02", DetectReferenceParseTest02, 1);
    UtRegisterTest("DetectReferenceParseTest03", DetectReferenceParseTest03, 1);
#endif /* UNITTESTS */

    return;
}
