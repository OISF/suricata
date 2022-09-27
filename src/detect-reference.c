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
 * \author Breno Silva <breno.silva@gmail.com>
 * \author Anoop Saldanha <anoopsaldanha@gmail.com>
 *
 * Implements the reference keyword support
 */

#include "suricata-common.h"
#include "detect-parse.h"

#include "util-reference-config.h"
#include "detect-reference.h"

#ifdef UNITTESTS
#include "util-unittest.h"
#include "detect-engine.h"
#endif
#define PARSE_REGEX "^\\s*([A-Za-z0-9]+)\\s*,\"?\\s*\"?\\s*([a-zA-Z0-9\\-_\\.\\/\\?\\=]+)\"?\\s*\"?"

static DetectParseRegex parse_regex;

#ifdef UNITTESTS
static void ReferenceRegisterTests(void);
#endif
static int DetectReferenceSetup(DetectEngineCtx *, Signature *s, const char *str);

/**
 * \brief Registration function for the reference: keyword
 */
void DetectReferenceRegister(void)
{
    sigmatch_table[DETECT_REFERENCE].name = "reference";
    sigmatch_table[DETECT_REFERENCE].desc = "direct to places where information about the rule can be found";
    sigmatch_table[DETECT_REFERENCE].url = "/rules/meta.html#reference";
    sigmatch_table[DETECT_REFERENCE].Setup = DetectReferenceSetup;
#ifdef UNITTESTS
    sigmatch_table[DETECT_REFERENCE].RegisterTests = ReferenceRegisterTests;
#endif
    DetectSetupParseRegexes(PARSE_REGEX, &parse_regex);
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
static DetectReference *DetectReferenceParse(const char *rawstr, DetectEngineCtx *de_ctx)
{
    SCEnter();

    int ret = 0, res = 0;
    size_t pcre2len;
    char key[REFERENCE_SYSTEM_NAME_MAX] = "";
    char content[REFERENCE_CONTENT_NAME_MAX] = "";

    ret = DetectParsePcreExec(&parse_regex, rawstr, 0, 0);
    if (ret < 2) {
        SCLogError(SC_ERR_INVALID_SIGNATURE, "Unable to parse \"reference\" "
                   "keyword argument - \"%s\".   Invalid argument.", rawstr);
        return NULL;
    }

    DetectReference *ref = SCCalloc(1, sizeof(DetectReference));
    if (unlikely(ref == NULL)) {
        return NULL;
    }

    pcre2len = sizeof(key);
    res = pcre2_substring_copy_bynumber(parse_regex.match, 1, (PCRE2_UCHAR8 *)key, &pcre2len);
    if (res < 0) {
        SCLogError(SC_ERR_PCRE_GET_SUBSTRING, "pcre2_substring_copy_bynumber failed");
        goto error;
    }

    pcre2len = sizeof(content);
    res = pcre2_substring_copy_bynumber(parse_regex.match, 2, (PCRE2_UCHAR8 *)content, &pcre2len);
    if (res < 0) {
        SCLogError(SC_ERR_PCRE_GET_SUBSTRING, "pcre2_substring_copy_bynumber failed");
        goto error;
    }

    if (strlen(key) == 0 || strlen(content) == 0)
        goto error;

    SCRConfReference *lookup_ref_conf = SCRConfGetReference(key, de_ctx);
    if (lookup_ref_conf != NULL) {
        ref->key = lookup_ref_conf->url;
    } else {
        if (SigMatchStrictEnabled(DETECT_REFERENCE)) {
            SCLogError(SC_ERR_REFERENCE_UNKNOWN,
                    "unknown reference key \"%s\"", key);
            goto error;
        }

        SCLogWarning(SC_ERR_REFERENCE_UNKNOWN,
                "unknown reference key \"%s\"", key);

        char str[2048];
        snprintf(str, sizeof(str), "config reference: %s undefined\n", key);

        if (SCRConfAddReference(de_ctx, str) < 0)
            goto error;
        lookup_ref_conf = SCRConfGetReference(key, de_ctx);
        if (lookup_ref_conf == NULL)
            goto error;
    }

    /* make a copy so we can free pcre's substring */
    ref->reference = SCStrdup(content);
    if (ref->reference == NULL) {
        SCLogError(SC_ERR_MEM_ALLOC, "strdup failed: %s", strerror(errno));
        goto error;
    }

    /* free the substrings */
    SCReturnPtr(ref, "Reference");

error:
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
                                const char *rawstr)
{
    SCEnter();

    DetectReference *sig_refs = NULL;

    DetectReference *ref = DetectReferenceParse(rawstr, de_ctx);
    if (ref == NULL)
        SCReturnInt(-1);

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
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);
    de_ctx->flags |= DE_QUIET;

    FILE *fd = SCRConfGenerateValidDummyReferenceConfigFD01();
    FAIL_IF_NULL(fd);
    SCRConfLoadReferenceConfigFile(de_ctx, fd);

    Signature *s = DetectEngineAppendSig(de_ctx, "alert icmp any any -> any any "
            "(msg:\"One reference\"; reference:one,001-2010; sid:2;)");
    FAIL_IF_NULL(s);
    FAIL_IF_NULL(s->references);

    DetectReference *ref = s->references;
    FAIL_IF (strcmp(ref->key, "http://www.one.com") != 0);
    FAIL_IF (strcmp(ref->reference, "001-2010") != 0);

    DetectEngineCtxFree(de_ctx);
    PASS;
}

/**
 * \test for two valid references.
 *
 *  \retval 1 on succces.
 *  \retval 0 on failure.
 */
static int DetectReferenceParseTest02(void)
{
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);
    de_ctx->flags |= DE_QUIET;

    FILE *fd = SCRConfGenerateValidDummyReferenceConfigFD01();
    FAIL_IF_NULL(fd);
    SCRConfLoadReferenceConfigFile(de_ctx, fd);

    Signature *s = DetectEngineAppendSig(de_ctx, "alert icmp any any -> any any "
                                   "(msg:\"Two references\"; "
                                   "reference:one,openinfosecdoundation.txt; "
                                   "reference:two,001-2010; sid:2;)");
    FAIL_IF_NULL(s);
    FAIL_IF_NULL(s->references);
    FAIL_IF_NULL(s->references->next);

    DetectReference *ref = s->references;
    FAIL_IF (strcmp(ref->key, "http://www.one.com") != 0);
    FAIL_IF (strcmp(ref->reference, "openinfosecdoundation.txt") != 0);

    ref = s->references->next;
    FAIL_IF (strcmp(ref->key, "http://www.two.com") != 0);
    FAIL_IF (strcmp(ref->reference, "001-2010") != 0);

    DetectEngineCtxFree(de_ctx);
    PASS;
}

/**
 * \test parsing: invalid reference.
 *
 *  \retval 1 on succces.
 *  \retval 0 on failure.
 */
static int DetectReferenceParseTest03(void)
{
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);
    de_ctx->flags |= DE_QUIET;

    FILE *fd = SCRConfGenerateValidDummyReferenceConfigFD01();
    FAIL_IF_NULL(fd);
    SCRConfLoadReferenceConfigFile(de_ctx, fd);

    Signature *s = DetectEngineAppendSig(de_ctx, "alert icmp any any -> any any "
                                   "(msg:\"invalid ref\"; "
                                   "reference:unknownkey,001-2010; sid:2;)");
    FAIL_IF_NULL(s);
    DetectEngineCtxFree(de_ctx);
    PASS;
}

static void ReferenceRegisterTests(void)
{
    UtRegisterTest("DetectReferenceParseTest01", DetectReferenceParseTest01);
    UtRegisterTest("DetectReferenceParseTest02", DetectReferenceParseTest02);
    UtRegisterTest("DetectReferenceParseTest03", DetectReferenceParseTest03);
}
#endif /* UNITTESTS */
