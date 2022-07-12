/* Copyright (C) 2015-2020 Open Information Security Foundation
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
 * Implements tls certificate validity keywords
 */

#include "suricata-common.h"
#include "threads.h"
#include "debug.h"
#include "decode.h"
#include "detect.h"

#include "detect-parse.h"
#include "detect-engine.h"
#include "detect-engine-mpm.h"
#include "detect-content.h"
#include "detect-pcre.h"
#include "detect-tls-cert-validity.h"

#include "flow.h"
#include "flow-util.h"
#include "flow-var.h"

#include "stream-tcp.h"

#include "app-layer.h"
#include "app-layer-ssl.h"

#include "util-time.h"
#include "util-unittest.h"
#include "util-unittest-helper.h"

/**
 *   [tls_notbefore|tls_notafter]:[<|>]<date string>[<><date string>];
 */
#define PARSE_REGEX "^\\s*(<|>)?\\s*([ -:TW0-9]+)\\s*(?:(<>)\\s*([ -:TW0-9]+))?\\s*$"
static DetectParseRegex parse_regex;

static int DetectTlsValidityMatch (DetectEngineThreadCtx *, Flow *,
                                   uint8_t, void *, void *, const Signature *,
                                   const SigMatchCtx *);

static time_t DateStringToEpoch (char *);
static DetectTlsValidityData *DetectTlsValidityParse (const char *);
static int DetectTlsExpiredSetup (DetectEngineCtx *, Signature *s, const char *str);
static int DetectTlsValidSetup (DetectEngineCtx *, Signature *s, const char *str);
static int DetectTlsNotBeforeSetup (DetectEngineCtx *, Signature *s, const char *str);
static int DetectTlsNotAfterSetup (DetectEngineCtx *, Signature *s, const char *str);
static int DetectTlsValiditySetup (DetectEngineCtx *, Signature *s, const char *str, uint8_t);
#ifdef UNITTESTS
static void TlsNotBeforeRegisterTests(void);
static void TlsNotAfterRegisterTests(void);
static void TlsExpiredRegisterTests(void);
static void TlsValidRegisterTests(void);
#endif /* UNITTESTS */
static void DetectTlsValidityFree(DetectEngineCtx *, void *);
static int g_tls_validity_buffer_id = 0;

/**
 * \brief Registration function for tls validity keywords.
 */
void DetectTlsValidityRegister (void)
{
    sigmatch_table[DETECT_AL_TLS_NOTBEFORE].name = "tls_cert_notbefore";
    sigmatch_table[DETECT_AL_TLS_NOTBEFORE].desc = "match TLS certificate notBefore field";
    sigmatch_table[DETECT_AL_TLS_NOTBEFORE].url = "/rules/tls-keywords.html#tls-cert-notbefore";
    sigmatch_table[DETECT_AL_TLS_NOTBEFORE].AppLayerTxMatch = DetectTlsValidityMatch;
    sigmatch_table[DETECT_AL_TLS_NOTBEFORE].Setup = DetectTlsNotBeforeSetup;
    sigmatch_table[DETECT_AL_TLS_NOTBEFORE].Free = DetectTlsValidityFree;
#ifdef UNITTESTS
    sigmatch_table[DETECT_AL_TLS_NOTBEFORE].RegisterTests = TlsNotBeforeRegisterTests;
#endif

    sigmatch_table[DETECT_AL_TLS_NOTAFTER].name = "tls_cert_notafter";
    sigmatch_table[DETECT_AL_TLS_NOTAFTER].desc = "match TLS certificate notAfter field";
    sigmatch_table[DETECT_AL_TLS_NOTAFTER].url = "/rules/tls-keywords.html#tls-cert-notafter";
    sigmatch_table[DETECT_AL_TLS_NOTAFTER].AppLayerTxMatch = DetectTlsValidityMatch;
    sigmatch_table[DETECT_AL_TLS_NOTAFTER].Setup = DetectTlsNotAfterSetup;
    sigmatch_table[DETECT_AL_TLS_NOTAFTER].Free = DetectTlsValidityFree;
#ifdef UNITTESTS
    sigmatch_table[DETECT_AL_TLS_NOTAFTER].RegisterTests = TlsNotAfterRegisterTests;
#endif

    sigmatch_table[DETECT_AL_TLS_EXPIRED].name = "tls_cert_expired";
    sigmatch_table[DETECT_AL_TLS_EXPIRED].desc = "match expired TLS certificates";
    sigmatch_table[DETECT_AL_TLS_EXPIRED].url = "/rules/tls-keywords.html#tls-cert-expired";
    sigmatch_table[DETECT_AL_TLS_EXPIRED].AppLayerTxMatch = DetectTlsValidityMatch;
    sigmatch_table[DETECT_AL_TLS_EXPIRED].Setup = DetectTlsExpiredSetup;
    sigmatch_table[DETECT_AL_TLS_EXPIRED].Free = DetectTlsValidityFree;
    sigmatch_table[DETECT_AL_TLS_EXPIRED].flags = SIGMATCH_NOOPT;
#ifdef UNITTESTS
    sigmatch_table[DETECT_AL_TLS_EXPIRED].RegisterTests = TlsExpiredRegisterTests;
#endif

    sigmatch_table[DETECT_AL_TLS_VALID].name = "tls_cert_valid";
    sigmatch_table[DETECT_AL_TLS_VALID].desc = "match valid TLS certificates";
    sigmatch_table[DETECT_AL_TLS_VALID].url = "/rules/tls-keywords.html#tls-cert-valid";
    sigmatch_table[DETECT_AL_TLS_VALID].AppLayerTxMatch = DetectTlsValidityMatch;
    sigmatch_table[DETECT_AL_TLS_VALID].Setup = DetectTlsValidSetup;
    sigmatch_table[DETECT_AL_TLS_VALID].Free = DetectTlsValidityFree;
    sigmatch_table[DETECT_AL_TLS_VALID].flags = SIGMATCH_NOOPT;
#ifdef UNITTESTS
    sigmatch_table[DETECT_AL_TLS_VALID].RegisterTests = TlsValidRegisterTests;
#endif

    DetectSetupParseRegexes(PARSE_REGEX, &parse_regex);

    DetectAppLayerInspectEngineRegister2("tls_validity", ALPROTO_TLS, SIG_FLAG_TOCLIENT,
            TLS_STATE_CERT_READY, DetectEngineInspectGenericList, NULL);

    g_tls_validity_buffer_id = DetectBufferTypeGetByName("tls_validity");
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
static int DetectTlsValidityMatch (DetectEngineThreadCtx *det_ctx,
                                   Flow *f, uint8_t flags, void *state,
                                   void *txv, const Signature *s,
                                   const SigMatchCtx *ctx)
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

    const DetectTlsValidityData *dd = (const DetectTlsValidityData *)ctx;

    time_t cert_epoch = 0;
    if (dd->type == DETECT_TLS_TYPE_NOTBEFORE)
        cert_epoch = connp->cert0_not_before;
    else if (dd->type == DETECT_TLS_TYPE_NOTAFTER)
        cert_epoch = connp->cert0_not_after;

    if (cert_epoch == 0)
        SCReturnInt(0);

    if ((dd->mode & DETECT_TLS_VALIDITY_EQ) && cert_epoch == dd->epoch)
        ret = 1;
    else if ((dd->mode & DETECT_TLS_VALIDITY_LT) && cert_epoch <= dd->epoch)
        ret = 1;
    else if ((dd->mode & DETECT_TLS_VALIDITY_GT) && cert_epoch >= dd->epoch)
        ret = 1;
    else if ((dd->mode & DETECT_TLS_VALIDITY_RA) &&
            cert_epoch >= dd->epoch && cert_epoch <= dd->epoch2)
        ret = 1;
    else if ((dd->mode & DETECT_TLS_VALIDITY_EX) &&
            f->lastts.tv_sec > cert_epoch)
        ret = 1;
    else if ((dd->mode & DETECT_TLS_VALIDITY_VA) &&
            f->lastts.tv_sec <= cert_epoch)
        ret = 1;

    SCReturnInt(ret);
}

/**
 * \internal
 * \brief Function to check if string is epoch.
 *
 * \param string Date string.
 *
 * \retval epoch time on success.
 * \retval 0 on failure.
 */
static time_t StringIsEpoch (char *string)
{
    if (strlen(string) == 0)
        return -1;

    /* We assume that the date string is epoch if it consists of only
       digits. */
    char *sp = string;
    while (*sp) {
        if (isdigit(*sp++) == 0)
            return -1;
    }

    return strtol(string, NULL, 10);
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
    const char *patterns[] = {
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
    };

    /* Skip leading whitespace.  */
    while (isspace(*string))
        string++;

    size_t inlen, oldlen;

    oldlen = inlen = strlen(string);

    /* Skip trailing whitespace */
    while (inlen > 0 && isspace(string[inlen - 1]))
        inlen--;

    char tmp[inlen + 1];

    if (inlen < oldlen) {
        strlcpy(tmp, string, inlen + 1);
        string = tmp;
    }

    time_t epoch = StringIsEpoch(string);
    if (epoch != -1) {
        return epoch;;
    }

    r = SCStringPatternToTime(string, patterns, 10, &tm);

    if (r != 0)
        return -1;

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
static DetectTlsValidityData *DetectTlsValidityParse (const char *rawstr)
{
    DetectTlsValidityData *dd = NULL;
    int ret = 0, res = 0;
    size_t pcre2len;
    char mode[2] = "";
    char value1[20] = "";
    char value2[20] = "";
    char range[3] = "";

    ret = DetectParsePcreExec(&parse_regex, rawstr, 0, 0);
    if (ret < 3 || ret > 5) {
        SCLogError(SC_ERR_PCRE_MATCH, "Parse error %s", rawstr);
        goto error;
    }

    pcre2len = sizeof(mode);
    res = SC_Pcre2SubstringCopy(parse_regex.match, 1, (PCRE2_UCHAR8 *)mode, &pcre2len);
    if (res < 0) {
        SCLogError(SC_ERR_PCRE_GET_SUBSTRING, "pcre2_substring_copy_bynumber failed");
        goto error;
    }
    SCLogDebug("mode \"%s\"", mode);

    pcre2len = sizeof(value1);
    res = pcre2_substring_copy_bynumber(parse_regex.match, 2, (PCRE2_UCHAR8 *)value1, &pcre2len);
    if (res < 0) {
        SCLogError(SC_ERR_PCRE_GET_SUBSTRING, "pcre2_substring_copy_bynumber failed");
        goto error;
    }
    SCLogDebug("value1 \"%s\"", value1);

    if (ret > 3) {
        pcre2len = sizeof(range);
        res = pcre2_substring_copy_bynumber(parse_regex.match, 3, (PCRE2_UCHAR8 *)range, &pcre2len);
        if (res < 0) {
            SCLogError(SC_ERR_PCRE_GET_SUBSTRING, "pcre2_substring_copy_bynumber failed");
            goto error;
        }
        SCLogDebug("range \"%s\"", range);

        if (ret > 4) {
            pcre2len = sizeof(value2);
            res = pcre2_substring_copy_bynumber(
                    parse_regex.match, 4, (PCRE2_UCHAR8 *)value2, &pcre2len);
            if (res < 0) {
                SCLogError(SC_ERR_PCRE_GET_SUBSTRING, "pcre2_substring_copy_bynumber failed");
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
    dd->mode = 0;

    if (strlen(mode) > 0) {
        if (mode[0] == '<')
            dd->mode |= DETECT_TLS_VALIDITY_LT;
        else if (mode[0] == '>')
            dd->mode |= DETECT_TLS_VALIDITY_GT;
    }

    if (strlen(range) > 0) {
        if (strcmp("<>", range) == 0)
            dd->mode |= DETECT_TLS_VALIDITY_RA;
    }

    if (strlen(range) != 0 && strlen(mode) != 0) {
        SCLogError(SC_ERR_INVALID_ARGUMENT,
                   "Range specified but mode also set");
        goto error;
    }

    if (dd->mode == 0) {
        dd->mode |= DETECT_TLS_VALIDITY_EQ;
    }

    /* set the first value */
    dd->epoch = DateStringToEpoch(value1);
    if (dd->epoch == -1)
        goto error;

    /* set the second value if specified */
    if (strlen(value2) > 0) {
        if (!(dd->mode & DETECT_TLS_VALIDITY_RA)) {
            SCLogError(SC_ERR_INVALID_ARGUMENT,
                "Multiple tls validity values specified but mode is not range");
            goto error;
        }

        dd->epoch2 = DateStringToEpoch(value2);
        if (dd->epoch2 == -1)
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
 * \brief Function to add the parsed tls_cert_expired into the current signature.
 *
 * \param de_ctx Pointer to the Detection Engine Context.
 * \param s      Pointer to the Current Signature.
 * \param rawstr Pointer to the user provided flags options.
 *
 * \retval 0 on Success.
 * \retval -1 on Failure.
 */
static int DetectTlsExpiredSetup (DetectEngineCtx *de_ctx, Signature *s,
                                  const char *rawstr)
{
    DetectTlsValidityData *dd = NULL;
    SigMatch *sm = NULL;

    SCLogDebug("\'%s\'", rawstr);

    if (DetectSignatureSetAppProto(s, ALPROTO_TLS) != 0)
        return -1;

    dd = SCCalloc(1, sizeof(DetectTlsValidityData));
    if (dd == NULL) {
        SCLogError(SC_ERR_INVALID_ARGUMENT,"Allocation \'%s\' failed", rawstr);
        goto error;
    }

    /* okay so far so good, lets get this into a SigMatch
     * and put it in the Signature. */
    sm = SigMatchAlloc();
    if (sm == NULL)
        goto error;

    dd->mode = DETECT_TLS_VALIDITY_EX;
    dd->type = DETECT_TLS_TYPE_NOTAFTER;
    dd->epoch = 0;
    dd->epoch2 = 0;

    sm->type = DETECT_AL_TLS_EXPIRED;
    sm->ctx = (void *)dd;

    SigMatchAppendSMToList(s, sm, g_tls_validity_buffer_id);
    return 0;

error:
    DetectTlsValidityFree(de_ctx, dd);
    if (sm)
        SCFree(sm);
    return -1;
}

/**
 * \brief Function to add the parsed tls_cert_valid into the current signature.
 *
 * \param de_ctx Pointer to the Detection Engine Context.
 * \param s      Pointer to the Current Signature.
 * \param rawstr Pointer to the user provided flags options.
 *
 * \retval 0 on Success.
 * \retval -1 on Failure.
 */
static int DetectTlsValidSetup (DetectEngineCtx *de_ctx, Signature *s,
                                const char *rawstr)
{
    DetectTlsValidityData *dd = NULL;
    SigMatch *sm = NULL;

    SCLogDebug("\'%s\'", rawstr);

    if (DetectSignatureSetAppProto(s, ALPROTO_TLS) != 0)
        return -1;

    dd = SCCalloc(1, sizeof(DetectTlsValidityData));
    if (dd == NULL) {
        SCLogError(SC_ERR_INVALID_ARGUMENT,"Allocation \'%s\' failed", rawstr);
        goto error;
    }

    /* okay so far so good, lets get this into a SigMatch
     * and put it in the Signature. */
    sm = SigMatchAlloc();
    if (sm == NULL)
        goto error;

    dd->mode = DETECT_TLS_VALIDITY_VA;
    dd->type = DETECT_TLS_TYPE_NOTAFTER;
    dd->epoch = 0;
    dd->epoch2 = 0;

    sm->type = DETECT_AL_TLS_VALID;
    sm->ctx = (void *)dd;

    SigMatchAppendSMToList(s, sm, g_tls_validity_buffer_id);
    return 0;

error:
    DetectTlsValidityFree(de_ctx, dd);
    if (sm)
        SCFree(sm);
    return -1;
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
                                    const char *rawstr)
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
                                   const char *rawstr)
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
                                   const char *rawstr, uint8_t type)
{
    DetectTlsValidityData *dd = NULL;
    SigMatch *sm = NULL;

    SCLogDebug("\'%s\'", rawstr);

    if (DetectSignatureSetAppProto(s, ALPROTO_TLS) != 0)
        return -1;

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

    SigMatchAppendSMToList(s, sm, g_tls_validity_buffer_id);
    return 0;

error:
    DetectTlsValidityFree(de_ctx, dd);
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
void DetectTlsValidityFree(DetectEngineCtx *de_ctx, void *de_ptr)
{
    DetectTlsValidityData *dd = (DetectTlsValidityData *)de_ptr;
    if (dd)
        SCFree(dd);
}

#ifdef UNITTESTS
#include "tests/detect-tls-cert-validity.c"
#endif
