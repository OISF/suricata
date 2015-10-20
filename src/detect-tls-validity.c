/* Copyright (C) 2015 Open Information Security Foundation
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
 * \author Mats Klepsland <mats.klepsland@gmail.com>
 *
 * Implements tls validity keywords
 */

#include "suricata-common.h"

#include "detect-parse.h"
#include "detect-tls-validity.h"

#include "app-layer.h"
#include "app-layer-ssl.h"

#include "util-time.h"
#include "util-unittest.h"

/**
 *   [tls_notbefore|tls_notafter]:[<|>]<date string>[<><date string>];
 */
#define PARSE_REGEX "^\\s*(<|>)?\\s*([ -:TW0-9]+)\\s*(?:(<>)\\s*([ -:TW0-9]+))?\\s*$"
static pcre *parse_regex;
static pcre_extra *parse_regex_study;

static int DetectTlsValidityMatch (ThreadVars *, DetectEngineThreadCtx *, Flow *,
                                   uint8_t, void *, Signature *, SigMatch *);
static time_t DateStringToEpoch (char *);
static DetectTlsValidityData *DetectTlsValidityParse (char *);
static int DetectTlsNotBeforeSetup (DetectEngineCtx *, Signature *s, char *str);
static int DetectTlsNotAfterSetup (DetectEngineCtx *, Signature *s, char *str);
static int DetectTlsValiditySetup (DetectEngineCtx *, Signature *s, char *str, uint8_t);
void TlsNotBeforeRegisterTests(void);
void TlsNotAfterRegisterTests(void);
static void DetectTlsValidityFree(void *);

/**
 * \brief Registration function for tls validity keywords.
 */
void DetectTlsValidityRegister (void)
{
    sigmatch_table[DETECT_AL_TLS_NOTBEFORE].name = "tls_notbefore";
    sigmatch_table[DETECT_AL_TLS_NOTBEFORE].desc = "match TLS certificate notBefore field";
    sigmatch_table[DETECT_AL_TLS_NOTBEFORE].url = "https://redmine.openinfosecfoundation.org/projects/suricata/wiki/TLS-keywords#tlsnotbefore";
    sigmatch_table[DETECT_AL_TLS_NOTBEFORE].Match = NULL;
    sigmatch_table[DETECT_AL_TLS_NOTBEFORE].AppLayerMatch = DetectTlsValidityMatch;
    sigmatch_table[DETECT_AL_TLS_NOTBEFORE].alproto = ALPROTO_TLS;
    sigmatch_table[DETECT_AL_TLS_NOTBEFORE].Setup = DetectTlsNotBeforeSetup;
    sigmatch_table[DETECT_AL_TLS_NOTBEFORE].Free = DetectTlsValidityFree;
    sigmatch_table[DETECT_AL_TLS_NOTBEFORE].RegisterTests = TlsNotBeforeRegisterTests;

    sigmatch_table[DETECT_AL_TLS_NOTAFTER].name = "tls_notafter";
    sigmatch_table[DETECT_AL_TLS_NOTAFTER].desc = "match TLS certificate notAfter field";
    sigmatch_table[DETECT_AL_TLS_NOTAFTER].url = "https://redmine.openinfosecfoundation.org/projects/suricata/wiki/TLS-keywords#tlsnotafter";
    sigmatch_table[DETECT_AL_TLS_NOTAFTER].Match = NULL;
    sigmatch_table[DETECT_AL_TLS_NOTAFTER].AppLayerMatch = DetectTlsValidityMatch;
    sigmatch_table[DETECT_AL_TLS_NOTAFTER].alproto = ALPROTO_TLS;
    sigmatch_table[DETECT_AL_TLS_NOTAFTER].Setup = DetectTlsNotAfterSetup;
    sigmatch_table[DETECT_AL_TLS_NOTAFTER].Free = DetectTlsValidityFree;
    sigmatch_table[DETECT_AL_TLS_NOTAFTER].RegisterTests = TlsNotAfterRegisterTests;

    const char *eb;
    int eo;
    int opts = 0;

    parse_regex = pcre_compile(PARSE_REGEX, opts, &eb, &eo, NULL);
    if (parse_regex == NULL) {
        SCLogError(SC_ERR_PCRE_COMPILE,"pcre compile of \"%s\" failed at offset %"
                   PRId32 ": %s", PARSE_REGEX, eo, eb);
        goto error;
    }

    parse_regex_study = pcre_study(parse_regex, 0, &eb);
    if (eb != NULL) {
        SCLogError(SC_ERR_PCRE_STUDY,"pcre study failed: %s", eb);
        goto error;
    }

error:
    return;
}

/**
 * \internal
 * \brief Function to match validity field in a tls certificate.
 *
 * \param t       Pointer to thread vars.
 * \param det_ctx Pointer to the pattern matcher thread.
 * \param f       Pointer to the current flow.
 * \param flags   Flags.
 * \param state   App layer state.
 * \param s       Pointer to the Signature.
 * \param m       Pointer to the sigmatch that we will cast into
 *                DetectTlsValidityData.
 *
 * \retval 0 no match.
 * \retval 1 match.
 */
static int DetectTlsValidityMatch (ThreadVars *t, DetectEngineThreadCtx *det_ctx,
                   Flow *f, uint8_t flags, void *state, Signature *s, SigMatch *m)
{
    SCEnter();

    SSLState *ssl_state = (SSLState *)state;
    if (ssl_state == NULL) {
        SCLogDebug("no tls state, no match");
        SCReturnInt(0);
    }

    int ret = 0;

    SSLStateConnp *connp = NULL;
    if (flags & STREAM_TOSERVER)
        connp = &ssl_state->client_connp;
    else
        connp = &ssl_state->server_connp;

    const DetectTlsValidityData *dd = (const DetectTlsValidityData *)m->ctx;

    time_t cert_epoch = 0;
    if (dd->type == DETECT_TLS_TYPE_NOTBEFORE)
        cert_epoch = connp->cert0_not_before;
    else if (dd->type == DETECT_TLS_TYPE_NOTAFTER)
        cert_epoch = connp->cert0_not_after;

    if (cert_epoch == 0)
        SCReturnInt(0);

    if (dd->mode == DETECT_TLS_VALIDITY_EQ && cert_epoch == dd->epoch)
        ret = 1;
    else if (dd->mode == DETECT_TLS_VALIDITY_LT && cert_epoch <= dd->epoch)
        ret = 1;
    else if (dd->mode == DETECT_TLS_VALIDITY_GT && cert_epoch >= dd->epoch)
        ret = 1;
    else if (dd->mode == DETECT_TLS_VALIDITY_RA &&
            cert_epoch >= dd->epoch && cert_epoch <= dd->epoch2)
        ret = 1;

    SCReturnInt(ret);
}

/**
 * \internal
 * \brief Function to convert date string to epoch.
 *
 * \param string Date string.
 *
 * \retval epoch on success.
 * \retval 0 on failure.
 */
static time_t DateStringToEpoch (char *string)
{
    int r = 0;
    struct tm tm;
    char *patterns[] = {
            /* ISO 8601 */
            "%Y-%m",
            "%Y-%m-%d",
            "%Y-%m-%d %H",
            "%Y-%m-%d %H:%M",
            "%Y-%m-%d %H:%M:%S",
            "%Y-%m-%dT%H",
            "%Y-%m-%dT%H:%M",
            "%Y-%m-%dT%H:%M:%S",
            "%H:%M",
            "%H:%M:%S",
            "%Y-%j",
            /* epoch */
            "%s"
    };

    r = SCStringPatternToTime(string, patterns, 12, &tm);

    if (r != 0)
        return 0;

    return SCMkTimeUtc(&tm);
}

/**
 * \internal
 * \brief Function to parse options passed via tls validity keywords.
 *
 * \param rawstr Pointer to the user provided options.
 *
 * \retval dd pointer to DetectTlsValidityData on success.
 * \retval NULL on failure.
 */
static DetectTlsValidityData *DetectTlsValidityParse (char *rawstr)
{
    DetectTlsValidityData *dd = NULL;
#define MAX_SUBSTRINGS 30
    int ret = 0, res = 0;
    int ov[MAX_SUBSTRINGS];
    char mode[2] = "";
    char value1[20] = "";
    char value2[20] = "";
    char range[3] = "";

    ret = pcre_exec(parse_regex, parse_regex_study, rawstr, strlen(rawstr), 0,
                    0, ov, MAX_SUBSTRINGS);
    if (ret < 3 || ret > 5) {
        SCLogError(SC_ERR_PCRE_MATCH, "Parse error %s", rawstr);
        goto error;
    }

    res = pcre_copy_substring((char *)rawstr, ov, MAX_SUBSTRINGS, 1, mode,
                              sizeof(mode));
    if (res < 0) {
        SCLogError(SC_ERR_PCRE_GET_SUBSTRING, "pcre_copy_substring failed");
        goto error;
    }
    SCLogDebug("mode \"%s\"", mode);

    res = pcre_copy_substring((char *)rawstr, ov, MAX_SUBSTRINGS, 2, value1,
                              sizeof(value1));
    if (res < 0) {
        SCLogError(SC_ERR_PCRE_GET_SUBSTRING, "pcre_copy_substring failed");
        goto error;
    }
    SCLogDebug("value1 \"%s\"", value1);

    if (ret > 3) {
        res = pcre_copy_substring((char *)rawstr, ov, MAX_SUBSTRINGS, 3,
                                  range, sizeof(range));
        if (res < 0) {
            SCLogError(SC_ERR_PCRE_GET_SUBSTRING, "pcre_copy_substring failed");
            goto error;
        }
        SCLogDebug("range \"%s\"", range);

        if (ret > 4) {
            res = pcre_copy_substring((char *)rawstr, ov, MAX_SUBSTRINGS, 4,
                                      value2, sizeof(value2));
            if (res < 0) {
                SCLogError(SC_ERR_PCRE_GET_SUBSTRING,
                           "pcre_copy_substring failed");
                goto error;
            }
            SCLogDebug("value2 \"%s\"", value2);
        }
    }

    dd = SCMalloc(sizeof(DetectTlsValidityData));
    if (unlikely(dd == NULL))
        goto error;

    dd->epoch = 0;
    dd->epoch2 = 0;
    dd->mode = DETECT_TLS_VALIDITY_EQ;

    if (strlen(mode) > 0) {
        if (mode[0] == '<')
            dd->mode = DETECT_TLS_VALIDITY_LT;
        else if (mode[0] == '>')
            dd->mode = DETECT_TLS_VALIDITY_GT;
        else
            dd->mode = DETECT_TLS_VALIDITY_EQ;
    }

    if (strlen(range) > 0) {
        if (strcmp("<>", range) == 0)
            dd->mode = DETECT_TLS_VALIDITY_RA;
    }

    if (strlen(range) != 0 && strlen(mode) != 0) {
        SCLogError(SC_ERR_INVALID_ARGUMENT,
                   "Range specified but mode also set");
        goto error;
    }

    /* set the first value */
    dd->epoch = DateStringToEpoch(value1);
    if (dd->epoch == 0)
        goto error;

    /* set the second value if specified */
    if (strlen(value2) > 0) {
        if (dd->mode != DETECT_TLS_VALIDITY_RA) {
            SCLogError(SC_ERR_INVALID_ARGUMENT,
                "Multiple tls validity values specified but mode is not range");
            goto error;
        }

        dd->epoch2 = DateStringToEpoch(value2);
        if (dd->epoch2 == 0)
            goto error;

        if (dd->epoch2 <= dd->epoch) {
            SCLogError(SC_ERR_INVALID_ARGUMENT,
                "Second value in range must not be smaller than the first");
            goto error;
        }
    }
    return dd;

error:
    if (dd)
        SCFree(dd);
    return NULL;
}

/**
 * \brief Function to add the parsed tls_notbefore into the current signature.
 *
 * \param de_ctx Pointer to the Detection Engine Context.
 * \param s      Pointer to the Current Signature.
 * \param rawstr Pointer to the user provided flags options.
 *
 * \retval 0 on Success.
 * \retval -1 on Failure.
 */
static int DetectTlsNotBeforeSetup (DetectEngineCtx *de_ctx, Signature *s,
                                    char *rawstr)
{
    uint8_t type = DETECT_TLS_TYPE_NOTBEFORE;
    int r = DetectTlsValiditySetup(de_ctx, s, rawstr, type);

    SCReturnInt(r);
}

/**
 * \brief Function to add the parsed tls_notafter into the current signature.
 *
 * \param de_ctx Pointer to the Detection Engine Context.
 * \param s      Pointer to the Current Signature.
 * \param rawstr Pointer to the user provided flags options.
 *
 * \retval 0 on Success.
 * \retval -1 on Failure.
 */
static int DetectTlsNotAfterSetup (DetectEngineCtx *de_ctx, Signature *s,
                                    char *rawstr)
{
    uint8_t type = DETECT_TLS_TYPE_NOTAFTER;
    int r = DetectTlsValiditySetup(de_ctx, s, rawstr, type);

    SCReturnInt(r);
}

/**
 * \brief Function to add the parsed tls validity field into the current signature.
 *
 * \param de_ctx Pointer to the Detection Engine Context.
 * \param s      Pointer to the Current Signature.
 * \param rawstr Pointer to the user provided flags options.
 * \param type   Defines if this is notBefore or notAfter.
 *
 * \retval 0 on Success.
 * \retval -1 on Failure.
 */
static int DetectTlsValiditySetup (DetectEngineCtx *de_ctx, Signature *s,
                                   char *rawstr, uint8_t type)
{
    DetectTlsValidityData *dd = NULL;
    SigMatch *sm = NULL;

    SCLogDebug("\'%s\'", rawstr);

    dd = DetectTlsValidityParse(rawstr);
    if (dd == NULL) {
        SCLogError(SC_ERR_INVALID_ARGUMENT,"Parsing \'%s\' failed", rawstr);
        goto error;
    }

    /* okay so far so good, lets get this into a SigMatch
     * and put it in the Signature. */
    sm = SigMatchAlloc();
    if (sm == NULL)
        goto error;

    if (s->alproto != ALPROTO_UNKNOWN && s->alproto != ALPROTO_TLS) {
        SCLogError(SC_ERR_CONFLICTING_RULE_KEYWORDS,
                   "rule contains conflicting keywords.");
        goto error;
    }

    if (type == DETECT_TLS_TYPE_NOTBEFORE) {
        dd->type = DETECT_TLS_TYPE_NOTBEFORE;
        sm->type = DETECT_AL_TLS_NOTBEFORE;
    }
    else if (type == DETECT_TLS_TYPE_NOTAFTER) {
        dd->type = DETECT_TLS_TYPE_NOTAFTER;
        sm->type = DETECT_AL_TLS_NOTAFTER;
    }
    else {
        goto error;
    }

    sm->ctx = (void *)dd;

    s->flags |= SIG_FLAG_APPLAYER;
    s->alproto = ALPROTO_TLS;

    SigMatchAppendSMToList(s, sm, DETECT_SM_LIST_AMATCH);

    return 0;

error:
    DetectTlsValidityFree(dd);
    if (sm)
        SCFree(sm);
    return -1;
}

/**
 * \internal
 * \brief Function to free memory associated with DetectTlsValidityData.
 *
 * \param de_ptr Pointer to DetectTlsValidityData.
 */
void DetectTlsValidityFree(void *de_ptr)
{
    DetectTlsValidityData *dd = (DetectTlsValidityData *)de_ptr;
    if (dd)
        SCFree(dd);
}

#ifdef UNITTESTS

/**
 * \test This is a test for a valid value 1430000000.
 *
 * \retval 1 on success.
 * \retval 0 on failure.
 */
int ValidityTestParse01 (void)
{
    int result = 0;
    DetectTlsValidityData *dd = NULL;
    dd = DetectTlsValidityParse("1430000000");
    if (dd) {
        if (dd->epoch == 1430000000 && dd->mode == DETECT_TLS_VALIDITY_EQ)
            result = 1;

        DetectTlsValidityFree(dd);
    }

    return result;
}

/**
 * \test This is a test for a valid value >1430000000.
 *
 * \retval 1 on success.
 * \retval 0 on failure.
 */
int ValidityTestParse02 (void)
{
    int result = 0;
    DetectTlsValidityData *dd = NULL;
    dd = DetectTlsValidityParse(">1430000000");
    if (dd) {
        if (dd->epoch == 1430000000 && dd->mode == DETECT_TLS_VALIDITY_GT)
            result = 1;

        DetectTlsValidityFree(dd);
    }

    return result;
}

/**
 * \test This is a test for a valid value <1430000000.
 *
 * \retval 1 on success.
 * \retval 0 on failure.
 */
int ValidityTestParse03 (void)
{
    int result = 0;
    DetectTlsValidityData *dd = NULL;
    dd = DetectTlsValidityParse("<1430000000");
    if (dd) {
        if (dd->epoch == 1430000000 && dd->mode == DETECT_TLS_VALIDITY_LT)
            result = 1;

        DetectTlsValidityFree(dd);
    }

    return result;
}

/**
 * \test This is a test for a valid value 1430000000<>1470000000.
 *
 * \retval 1 on success.
 * \retval 0 on failure.
 */
int ValidityTestParse04 (void)
{
    int result = 0;
    DetectTlsValidityData *dd = NULL;
    dd = DetectTlsValidityParse("1430000000<>1470000000");
    if (dd) {
        if (dd->epoch == 1430000000 && dd->epoch2 == 1470000000 &&
                dd->mode == DETECT_TLS_VALIDITY_RA)
            result = 1;

        DetectTlsValidityFree(dd);
    }

    return result;
}

/**
 * \test This is a test for a invalid value A.
 *
 * \retval 1 on success.
 * \retval 0 on failure.
 */
int ValidityTestParse05 (void)
{
    DetectTlsValidityData *dd = NULL;
    dd = DetectTlsValidityParse("A");
    if (dd) {
        DetectTlsValidityFree(dd);
        return 0;
    }

    return 1;
}

/**
 * \test This is a test for a invalid value >1430000000<>1470000000.
 *
 * \retval 1 on success.
 * \retval 0 on failure.
 */
int ValidityTestParse06 (void)
{
    DetectTlsValidityData *dd = NULL;
    dd = DetectTlsValidityParse(">1430000000<>1470000000");
    if (dd) {
        DetectTlsValidityFree(dd);
        return 0;
    }

    return 1;
}

/**
 * \test This is a test for a invalid value 1430000000<>.
 *
 * \retval 1 on success.
 * \retval 0 on failure.
 */
int ValidityTestParse07 (void)
{
    DetectTlsValidityData *dd = NULL;
    dd = DetectTlsValidityParse("1430000000<>");
    if (dd) {
        DetectTlsValidityFree(dd);
        return 0;
    }

    return 1;
}

/**
 * \test This is a test for a invalid value <>1430000000.
 *
 * \retval 1 on success.
 * \retval 0 on failure.
 */
int ValidityTestParse08 (void)
{
    DetectTlsValidityData *dd = NULL;
    dd = DetectTlsValidityParse("<>1430000000");
    if (dd) {
        DetectTlsValidityFree(dd);
        return 0;
    }

    return 1;
}

/**
 * \test This is a test for a invalid value "".
 *
 * \retval 1 on success.
 * \retval 0 on failure.
 */
int ValidityTestParse09 (void)
{
    DetectTlsValidityData *dd = NULL;
    dd = DetectTlsValidityParse("");
    if (dd) {
        DetectTlsValidityFree(dd);
        return 0;
    }

    return 1;
}

/**
 * \test This is a test for a invalid value " ".
 *
 * \retval 1 on success.
 * \retval 0 on failure.
 */
int ValidityTestParse10 (void)
{
    DetectTlsValidityData *dd = NULL;
    dd = DetectTlsValidityParse(" ");
    if (dd) {
        DetectTlsValidityFree(dd);
        return 0;
    }

    return 1;
}

/**
 * \test This is a test for a invalid value 1490000000<>1430000000.
 *
 * \retval 1 on success.
 * \retval 0 on failure.
 */
int ValidityTestParse11 (void)
{
    DetectTlsValidityData *dd = NULL;
    dd = DetectTlsValidityParse("1490000000<>1430000000");
    if (dd) {
        DetectTlsValidityFree(dd);
        return 0;
    }

    return 1;
}

/**
 * \test This is a test for a valid value 1430000000 <> 1490000000.
 *
 * \retval 1 on success.
 * \retval 0 on failure.
 */
int ValidityTestParse12 (void)
{
    int result = 0;
    DetectTlsValidityData *dd = NULL;
    dd = DetectTlsValidityParse("1430000000 <> 1490000000");
    if (dd) {
        if (dd->epoch == 1430000000 && dd->epoch2 == 1490000000 &&
                dd->mode == DETECT_TLS_VALIDITY_RA)
            result = 1;

        DetectTlsValidityFree(dd);
    }

    return result;
}

/**
 * \test This is a test for a valid value > 1430000000.
 *
 * \retval 1 on success.
 * \retval 0 on failure.
 */
int ValidityTestParse13 (void)
{
    int result = 0;
    DetectTlsValidityData *dd = NULL;
    dd = DetectTlsValidityParse("> 1430000000 ");
    if (dd) {
        if (dd->epoch == 1430000000 && dd->mode == DETECT_TLS_VALIDITY_GT)
            result = 1;

        DetectTlsValidityFree(dd);
    }

    return result;
}

/**
 * \test This is a test for a valid value <   1490000000.
 *
 * \retval 1 on success.
 * \retval 0 on failure.
 */
int ValidityTestParse14 (void)
{
    int result = 0;
    DetectTlsValidityData *dd = NULL;
    dd = DetectTlsValidityParse("<   1490000000 ");
    if (dd) {
        if (dd->epoch == 1490000000 && dd->mode == DETECT_TLS_VALIDITY_LT)
            result = 1;

        DetectTlsValidityFree(dd);
    }

    return result;
}

/**
 * \test This is a test for a valid value    1490000000.
 *
 * \retval 1 on success.
 * \retval 0 on failure.
 */
int ValidityTestParse15 (void)
{
    int result = 0;
    DetectTlsValidityData *dd = NULL;
    dd = DetectTlsValidityParse("   1490000000 ");
    if (dd) {
        if (dd->epoch == 1490000000 && dd->mode == DETECT_TLS_VALIDITY_EQ)
            result = 1;

        DetectTlsValidityFree(dd);
    }

    return result;
}

/**
 * \test This is a test for a valid value 2015-10.
 *
 * \retval 1 on success.
 * \retval 0 on failure.
 */
int ValidityTestParse16 (void)
{
    int result = 0;
    DetectTlsValidityData *dd = NULL;
    dd = DetectTlsValidityParse("2015-10");
    if (dd) {
        if (dd->epoch == 1443657600 && dd->mode == DETECT_TLS_VALIDITY_EQ)
            result = 1;

        DetectTlsValidityFree(dd);
    }

    return result;
}

/**
 * \test This is a test for a valid value >2015-10-22.
 *
 * \retval 1 on success.
 * \retval 0 on failure.
 */
int ValidityTestParse17 (void)
{
    int result = 0;
    DetectTlsValidityData *dd = NULL;
    dd = DetectTlsValidityParse(">2015-10-22");
    if (dd) {
        if (dd->epoch == 1445472000 && dd->mode == DETECT_TLS_VALIDITY_GT)
            result = 1;

        DetectTlsValidityFree(dd);
    }

    return result;
}

/**
 * \test This is a test for a valid value <2015-10-22 23.
 *
 * \retval 1 on success.
 * \retval 0 on failure.
 */
int ValidityTestParse18 (void)
{
    int result = 0;
    DetectTlsValidityData *dd = NULL;
    dd = DetectTlsValidityParse("<2015-10-22 23");
    if (dd) {
        if (dd->epoch == 1445554800 && dd->mode == DETECT_TLS_VALIDITY_LT)
            result = 1;

        DetectTlsValidityFree(dd);
    }

    return result;
}

/**
 * \test This is a test for a valid value 2015-10-22 23:59.
 *
 * \retval 1 on success.
 * \retval 0 on failure.
 */
int ValidityTestParse19 (void)
{
    int result = 0;
    DetectTlsValidityData *dd = NULL;
    dd = DetectTlsValidityParse("2015-10-22 23:59");
    if (dd) {
        if (dd->epoch == 1445558340 && dd->mode == DETECT_TLS_VALIDITY_EQ)
            result = 1;

        DetectTlsValidityFree(dd);
    }

    return result;
}

/**
 * \test This is a test for a valid value 2015-10-22 23:59:59.
 *
 * \retval 1 on success.
 * \retval 0 on failure.
 */
int ValidityTestParse20 (void)
{
    int result = 0;
    DetectTlsValidityData *dd = NULL;
    dd = DetectTlsValidityParse("2015-10-22 23:59:59");
    if (dd) {
        if (dd->epoch == 1445558399 && dd->mode == DETECT_TLS_VALIDITY_EQ)
            result = 1;

        DetectTlsValidityFree(dd);
    }

    return result;
}

/**
 * \test This is a test for a valid value 2015-10-22T23.
 *
 * \retval 1 on success.
 * \retval 0 on failure.
 */
int ValidityTestParse21 (void)
{
    int result = 0;
    DetectTlsValidityData *dd = NULL;
    dd = DetectTlsValidityParse("2015-10-22T23");
    if (dd) {
        if (dd->epoch == 1445554800 && dd->mode == DETECT_TLS_VALIDITY_EQ)
            result = 1;

        DetectTlsValidityFree(dd);
    }

    return result;
}

/**
 * \test This is a test for a valid value 2015-10-22T23:59.
 *
 * \retval 1 on success.
 * \retval 0 on failure.
 */
int ValidityTestParse22 (void)
{
    int result = 0;
    DetectTlsValidityData *dd = NULL;
    dd = DetectTlsValidityParse("2015-10-22T23:59");
    if (dd) {
        if (dd->epoch == 1445558340 && dd->mode == DETECT_TLS_VALIDITY_EQ)
            result = 1;

        DetectTlsValidityFree(dd);
    }

    return result;
}

/**
 * \test This is a test for a valid value 2015-10-22T23:59:59.
 *
 * \retval 1 on success.
 * \retval 0 on failure.
 */
int ValidityTestParse23 (void)
{
    int result = 0;
    DetectTlsValidityData *dd = NULL;
    dd = DetectTlsValidityParse("2015-10-22T23:59:59");
    if (dd) {
        if (dd->epoch == 1445558399 && dd->mode == DETECT_TLS_VALIDITY_EQ)
            result = 1;

        DetectTlsValidityFree(dd);
    }

    return result;
}

/**
 * \test This is a test for a valid value 2015-299.
 *
 * \retval 1 on success.
 * \retval 0 on failure.
 */
int ValidityTestParse24 (void)
{
    int result = 0;
    DetectTlsValidityData *dd = NULL;
    dd = DetectTlsValidityParse("2015-299");
    if (dd) {
        if (dd->epoch == 1445817600 && dd->mode == DETECT_TLS_VALIDITY_EQ)
            result = 1;

        DetectTlsValidityFree(dd);
    }

    return result;
}

#endif /* UNITTESTS */

/**
 * \brief Register unit tests for tls_notbefore.
 */
void TlsNotBeforeRegisterTests(void)
{
#ifdef UNITTESTS /* UNITTESTS */
    UtRegisterTest("ValidityTestParse01", ValidityTestParse01, 1);
    UtRegisterTest("ValidityTestParse03", ValidityTestParse03, 1);
    UtRegisterTest("ValidityTestParse05", ValidityTestParse05, 1);
    UtRegisterTest("ValidityTestParse07", ValidityTestParse07, 1);
    UtRegisterTest("ValidityTestParse09", ValidityTestParse09, 1);
    UtRegisterTest("ValidityTestParse11", ValidityTestParse11, 1);
    UtRegisterTest("ValidityTestParse13", ValidityTestParse13, 1);
    UtRegisterTest("ValidityTestParse15", ValidityTestParse15, 1);
    UtRegisterTest("ValidityTestParse17", ValidityTestParse17, 1);
    UtRegisterTest("ValidityTestParse19", ValidityTestParse19, 1);
    UtRegisterTest("ValidityTestParse21", ValidityTestParse21, 1);
    UtRegisterTest("ValidityTestParse23", ValidityTestParse23, 1);
#endif /* UNITTESTS */
}

/**
 * \brief Register unit tests for tls_notafter.
 */
void TlsNotAfterRegisterTests(void)
{
#ifdef UNITTESTS /* UNITTESTS */
    UtRegisterTest("ValidityTestParse02", ValidityTestParse02, 1);
    UtRegisterTest("ValidityTestParse04", ValidityTestParse04, 1);
    UtRegisterTest("ValidityTestParse06", ValidityTestParse06, 1);
    UtRegisterTest("ValidityTestParse08", ValidityTestParse08, 1);
    UtRegisterTest("ValidityTestParse10", ValidityTestParse10, 1);
    UtRegisterTest("ValidityTestParse12", ValidityTestParse12, 1);
    UtRegisterTest("ValidityTestParse14", ValidityTestParse14, 1);
    UtRegisterTest("ValidityTestParse16", ValidityTestParse16, 1);
    UtRegisterTest("ValidityTestParse18", ValidityTestParse18, 1);
    UtRegisterTest("ValidityTestParse20", ValidityTestParse20, 1);
    UtRegisterTest("ValidityTestParse22", ValidityTestParse22, 1);
    UtRegisterTest("ValidityTestParse24", ValidityTestParse24, 1);
#endif /* UNITTESTS */
}
