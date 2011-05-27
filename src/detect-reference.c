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
#include "detect.h"
#include "flow-var.h"
#include "decode-events.h"
#include "stream-tcp.h"

#include "detect-reference.h"

#include "util-unittest.h"
#include "util-byte.h"
#include "util-debug.h"

#define PARSE_REGEX "^\\s*(cve|nessus|url|mcafee|bugtraq|arachnids)\\s*,\"?\\s*\"?\\s*([a-zA-Z0-9\\-_\\.\\/\\?\\=]+)\"?\\s*\"?"

/* Static prefix for references - Maybe we should move them to reference.config in the future */
char REFERENCE_BUGTRAQ[] =   "http://www.securityfocus.com/bid/";
char REFERENCE_CVE[] =       "http://cve.mitre.org/cgi-bin/cvename.cgi?name=";
char REFERENCE_NESSUS[] =    "http://cgi.nessus.org/plugins/dump.php3?id=";
char REFERENCE_ARACHNIDS[] = "http://www.whitehats.com/info/IDS";
char REFERENCE_MCAFEE[] =    "http://vil.nai.com/vil/dispVirus.asp?virus_k=";
char REFERENCE_URL[] =       "http://";

static pcre *parse_regex;
static pcre_extra *parse_regex_study;

static int DetectReferenceSetup (DetectEngineCtx *, Signature *s, char *str);

/**
 * \brief Registration function for reference: keyword
 */

void DetectReferenceRegister (void) {
    sigmatch_table[DETECT_REFERENCE].name = "reference";
    sigmatch_table[DETECT_REFERENCE].Match = NULL;
    sigmatch_table[DETECT_REFERENCE].Setup = DetectReferenceSetup;
    sigmatch_table[DETECT_REFERENCE].Free  = NULL;
    sigmatch_table[DETECT_REFERENCE].RegisterTests = ReferenceRegisterTests;

    const char *eb;
    int opts = 0;
    int eo;

    opts |= PCRE_CASELESS;

    parse_regex = pcre_compile(PARSE_REGEX, opts, &eb, &eo, NULL);
    if (parse_regex == NULL)
    {
        SCLogError(SC_ERR_PCRE_COMPILE, "pcre compile of \"%s\" failed at offset %" PRId32 ": %s", PARSE_REGEX, eo, eb);
        goto error;
    }

    parse_regex_study = pcre_study(parse_regex, 0, &eb);
    if (eb != NULL)
    {
        SCLogError(SC_ERR_PCRE_STUDY, "pcre study failed: %s", eb);
        goto error;
    }

error:
    return;

}

/**
 *  \brief Free a Reference object
 */
void DetectReferenceFree(Reference *ref) {
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
 * \param rawstr Pointer to the user provided reference options
 *
 * \retval ref pointer to signature reference on success
 * \retval NULL on failure
 */
static Reference *DetectReferenceParse (char *rawstr)
{
    SCEnter();

    Reference *ref = NULL;
    char *str = NULL;
#define MAX_SUBSTRINGS 30
    int ret = 0, res = 0;
    int ov[MAX_SUBSTRINGS];
    const char *ref_key = NULL;
    const char *ref_content = NULL;

    ret = pcre_exec(parse_regex, parse_regex_study, rawstr, strlen(rawstr), 0, 0, ov, MAX_SUBSTRINGS);
    if (ret < 2) {
        SCLogError(SC_ERR_PCRE_MATCH, "pcre_exec parse error, ret %" PRId32 ", string %s", ret, rawstr);
        goto error;
    }

    ref = SCMalloc(sizeof(Reference));
    if (ref == NULL) {
        SCLogError(SC_ERR_MEM_ALLOC, "malloc failed: %s", strerror(errno));
        goto error;
    }
    memset(ref, 0, sizeof(Reference));

    res = pcre_get_substring((char *)rawstr, ov, MAX_SUBSTRINGS,1, &ref_key);
    if (res < 0) {
        SCLogError(SC_ERR_PCRE_GET_SUBSTRING, "pcre_get_substring failed");
        goto error;
    }

    res = pcre_get_substring((char *)rawstr, ov, MAX_SUBSTRINGS,2, &ref_content);
    if (res < 0) {
        SCLogError(SC_ERR_PCRE_GET_SUBSTRING, "pcre_get_substring failed");
        goto error;
    }

    if (ref_key == NULL || ref_content == NULL)
        goto error;

    if (strcasecmp(ref_key,"cve") == 0)  {
        ref->key = REFERENCE_CVE;
    } else if (strcasecmp(ref_key,"bugtraq") == 0) {
        ref->key = REFERENCE_BUGTRAQ;
    } else if (strcasecmp(ref_key,"nessus") == 0) {
        ref->key = REFERENCE_NESSUS;
    } else if (strcasecmp(ref_key,"url") == 0) {
        ref->key = REFERENCE_URL;
    } else if (strcasecmp(ref_key,"mcafee") == 0) {
        ref->key = REFERENCE_MCAFEE;
    } else if (strcasecmp(ref_key,"arachnids") == 0) {
        ref->key = REFERENCE_ARACHNIDS;
    } else {
        SCLogError(SC_ERR_REFERENCE_UNKNOWN, "unknown reference key \"%s\". "
                "Supported keys are cve, bugtraq, nessus, url, mcafee, "
                "arachnids.", ref_key);
        goto error;
    }

    /* make a copy so we can free pcre's substring */
    str = SCStrdup((char *)ref_content);
    if (str == NULL) {
        SCLogError(SC_ERR_MEM_ALLOC, "strdup failed: %s", strerror(errno));
        goto error;
    }

    ref->reference = str;

    /* free the substrings */
    pcre_free_substring(ref_key);
    pcre_free_substring(ref_content);

    SCReturnPtr(ref, "Reference");

error:
    if (ref_key != NULL) {
        pcre_free_substring(ref_key);
    }
    if (ref_content != NULL) {
        pcre_free_substring(ref_content);
    }

    if (ref != NULL) {
        DetectReferenceFree(ref);
    }

    SCReturnPtr(NULL, "Reference");
}

/**
 * \internal
 * \brief this function is used to add the parsed reference into the current signature
 *
 * \param de_ctx pointer to the Detection Engine Context
 * \param s pointer to the Current Signature
 * \param m pointer to the Current SigMatch
 * \param rawstr pointer to the user provided reference options
 *
 * \retval 0 on Success
 * \retval -1 on Failure
 */
static int DetectReferenceSetup (DetectEngineCtx *de_ctx, Signature *s, char *rawstr)
{
    SCEnter();

    Reference *ref = NULL;
    Reference *actual_reference = NULL;

    ref = DetectReferenceParse(rawstr);
    if (ref == NULL)
        goto error;

    SCLogDebug("ref %s %s", ref->key, ref->reference);

    if (s->references == NULL)  {
        s->references = ref;
        ref->next = NULL;
    } else {
        actual_reference = s->references;

        while (actual_reference->next != NULL)    {
            actual_reference = actual_reference->next;
        }

        actual_reference->next = ref;
        ref->next = NULL;
    }

    SCLogDebug("s->references %p", s->references);
    SCReturnInt(0);

error:
    SCReturnInt(-1);
}

/*
 * ONLY TESTS BELOW THIS COMMENT
 */
#ifdef UNITTESTS

/**
 * \test one valid reference.
 *
 *  \retval 1 on succces
 *  \retval 0 on failure
 */
static int DetectReferenceParseTest01(void)
{
    int result = 0;
    Signature *s = NULL;
    Reference *ref = NULL;

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        goto cleanup;
    }

    de_ctx->flags |= DE_QUIET;

    s = de_ctx->sig_list = SigInit(de_ctx, "alert icmp any any -> any any (msg:\"One reference\"; reference:cve,001-2010; sid:2;)");

    if (s == NULL) {
        goto cleanup;
    }

    if (s->references == NULL)  {
        goto cleanup;
    }

    ref = s->references;
    if (strcmp(ref->key,"http://cve.mitre.org/cgi-bin/cvename.cgi?name=") != 0 ||
            strcmp(ref->reference,"001-2010") != 0)  {
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
 *  \retval 1 on succces
 *  \retval 0 on failure
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

    s = de_ctx->sig_list = SigInit(de_ctx, "alert icmp any any -> any any (msg:\"Two references\"; reference:url,www.openinfosecfoundation.org; reference:cve,001-2010; sid:2;)");
    if (s == NULL) {
        printf("sig parse failed: ");
        goto cleanup;
    }

    if (s->references == NULL || s->references->next == NULL)  {
        printf("no ref or not enough refs: ");
        goto cleanup;
    }

    if (strcmp(s->references->key, "http://") != 0 ||
            strcmp(s->references->reference, "www.openinfosecfoundation.org") != 0) {
        printf("first ref failed: ");
        goto cleanup;

    }

    if (strcmp(s->references->next->key,
                "http://cve.mitre.org/cgi-bin/cvename.cgi?name=") != 0 ||
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
 * \test parsing: invalid reference
 *
 *  \retval 1 on succces
 *  \retval 0 on failure
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

    s = de_ctx->sig_list = SigInit(de_ctx, "alert icmp any any -> any any (msg:\"invalid ref\"; reference:unknownkey,001-2010; sid:2;)");
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

void ReferenceRegisterTests(void) {
#ifdef UNITTESTS
    UtRegisterTest("DetectReferenceParseTest01", DetectReferenceParseTest01, 1);
    UtRegisterTest("DetectReferenceParseTest02", DetectReferenceParseTest02, 1);
    UtRegisterTest("DetectReferenceParseTest03", DetectReferenceParseTest03, 1);
#endif /* UNITTESTS */
}
