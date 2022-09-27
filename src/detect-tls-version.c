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
 * Implements the tls.version keyword
 */

#include "suricata-common.h"

#include "detect-parse.h"

#include "detect-engine.h"

#include "app-layer-ssl.h"
#include "detect-tls-version.h"

#ifdef UNITTESTS
#include "util-unittest.h"
#endif
/**
 * \brief Regex for parsing "id" option, matching number or "number"
 */
#define PARSE_REGEX  "^\\s*([A-z0-9\\.]+|\"[A-z0-9\\.]+\")\\s*$"

static DetectParseRegex parse_regex;

static int DetectTlsVersionMatch (DetectEngineThreadCtx *,
        Flow *, uint8_t, void *, void *,
        const Signature *, const SigMatchCtx *);
static int DetectTlsVersionSetup (DetectEngineCtx *, Signature *, const char *);
#ifdef UNITTESTS
static void DetectTlsVersionRegisterTests(void);
#endif
static void DetectTlsVersionFree(DetectEngineCtx *, void *);
static int g_tls_generic_list_id = 0;

/**
 * \brief Registration function for keyword: tls.version
 */
void DetectTlsVersionRegister (void)
{
    sigmatch_table[DETECT_AL_TLS_VERSION].name = "tls.version";
    sigmatch_table[DETECT_AL_TLS_VERSION].desc = "match on TLS/SSL version";
    sigmatch_table[DETECT_AL_TLS_VERSION].url = "/rules/tls-keywords.html#tls-version";
    sigmatch_table[DETECT_AL_TLS_VERSION].AppLayerTxMatch = DetectTlsVersionMatch;
    sigmatch_table[DETECT_AL_TLS_VERSION].Setup = DetectTlsVersionSetup;
    sigmatch_table[DETECT_AL_TLS_VERSION].Free  = DetectTlsVersionFree;
#ifdef UNITTESTS
    sigmatch_table[DETECT_AL_TLS_VERSION].RegisterTests = DetectTlsVersionRegisterTests;
#endif

    DetectSetupParseRegexes(PARSE_REGEX, &parse_regex);

    g_tls_generic_list_id = DetectBufferTypeRegister("tls_generic");
}

/**
 * \brief match the specified version on a tls session
 *
 * \param t pointer to thread vars
 * \param det_ctx pointer to the pattern matcher thread
 * \param p pointer to the current packet
 * \param m pointer to the sigmatch that we will cast into DetectTlsVersionData
 *
 * \retval 0 no match
 * \retval 1 match
 */
static int DetectTlsVersionMatch (DetectEngineThreadCtx *det_ctx,
        Flow *f, uint8_t flags, void *state, void *txv,
        const Signature *s, const SigMatchCtx *m)
{
    SCEnter();

    const DetectTlsVersionData *tls_data = (const DetectTlsVersionData *)m;
    SSLState *ssl_state = (SSLState *)state;
    if (ssl_state == NULL) {
        SCLogDebug("no tls state, no match");
        SCReturnInt(0);
    }

    int ret = 0;
    uint16_t version = 0;
    SCLogDebug("looking for tls_data->ver 0x%02X (flags 0x%02X)", tls_data->ver, flags);

    if (flags & STREAM_TOCLIENT) {
        version = ssl_state->server_connp.version;
        SCLogDebug("server (toclient) version is 0x%02X", version);
    } else if (flags & STREAM_TOSERVER) {
        version =  ssl_state->client_connp.version;
        SCLogDebug("client (toserver) version is 0x%02X", version);
    }

    if ((tls_data->flags & DETECT_TLS_VERSION_FLAG_RAW) == 0) {
        /* Match all TLSv1.3 drafts as TLSv1.3 */
        if (((version >> 8) & 0xff) == 0x7f) {
            version = TLS_VERSION_13;
        }
    }

    if (tls_data->ver == version) {
        ret = 1;
    }

    SCReturnInt(ret);
}

/**
 * \brief This function is used to parse IPV4 ip_id passed via keyword: "id"
 *
 * \param de_ctx Pointer to the detection engine context
 * \param idstr Pointer to the user provided id option
 *
 * \retval id_d pointer to DetectTlsVersionData on success
 * \retval NULL on failure
 */
static DetectTlsVersionData *DetectTlsVersionParse (DetectEngineCtx *de_ctx, const char *str)
{
    uint16_t temp;
    DetectTlsVersionData *tls = NULL;
    int ret = 0, res = 0;
    size_t pcre2len;

    ret = DetectParsePcreExec(&parse_regex, str, 0, 0);
    if (ret < 1 || ret > 3) {
        SCLogError(SC_ERR_PCRE_MATCH, "invalid tls.version option");
        goto error;
    }

    if (ret > 1) {
        char ver_ptr[64];
        char *tmp_str;
        pcre2len = sizeof(ver_ptr);
        res = pcre2_substring_copy_bynumber(
                parse_regex.match, 1, (PCRE2_UCHAR8 *)ver_ptr, &pcre2len);
        if (res < 0) {
            SCLogError(SC_ERR_PCRE_GET_SUBSTRING, "pcre2_substring_copy_bynumber failed");
            goto error;
        }

        /* We have a correct id option */
        tls = SCCalloc(1, sizeof(DetectTlsVersionData));
        if (unlikely(tls == NULL))
            goto error;

        tmp_str = ver_ptr;

        /* Let's see if we need to scape "'s */
        if (tmp_str[0] == '"')
        {
            tmp_str[strlen(tmp_str) - 1] = '\0';
            tmp_str += 1;
        }

        if (strncmp("1.0", tmp_str, 3) == 0) {
            temp = TLS_VERSION_10;
        } else if (strncmp("1.1", tmp_str, 3) == 0) {
            temp = TLS_VERSION_11;
        } else if (strncmp("1.2", tmp_str, 3) == 0) {
            temp = TLS_VERSION_12;
        } else if (strncmp("1.3", tmp_str, 3) == 0) {
            temp = TLS_VERSION_13;
        } else if ((strncmp("0x", tmp_str, 2) == 0) && (strlen(str) == 6)) {
            temp = (uint16_t)strtol(tmp_str, NULL, 0);
            tls->flags |= DETECT_TLS_VERSION_FLAG_RAW;
        } else {
            SCLogError(SC_ERR_INVALID_VALUE, "Invalid value");
            goto error;
        }

        tls->ver = temp;

        SCLogDebug("will look for tls %"PRIu16"", tls->ver);
    }

    return tls;

error:
    if (tls != NULL)
        DetectTlsVersionFree(de_ctx, tls);
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
static int DetectTlsVersionSetup (DetectEngineCtx *de_ctx, Signature *s, const char *str)
{
    DetectTlsVersionData *tls = NULL;
    SigMatch *sm = NULL;

    if (DetectSignatureSetAppProto(s, ALPROTO_TLS) != 0)
        return -1;

    tls = DetectTlsVersionParse(de_ctx, str);
    if (tls == NULL)
        goto error;

    /* Okay so far so good, lets get this into a SigMatch
     * and put it in the Signature. */
    sm = SigMatchAlloc();
    if (sm == NULL)
        goto error;

    sm->type = DETECT_AL_TLS_VERSION;
    sm->ctx = (void *)tls;

    SigMatchAppendSMToList(s, sm, g_tls_generic_list_id);

    return 0;

error:
    if (tls != NULL)
        DetectTlsVersionFree(de_ctx, tls);
    if (sm != NULL)
        SCFree(sm);
    return -1;

}

/**
 * \brief this function will free memory associated with DetectTlsVersionData
 *
 * \param id_d pointer to DetectTlsVersionData
 */
static void DetectTlsVersionFree(DetectEngineCtx *de_ctx, void *ptr)
{
    DetectTlsVersionData *id_d = (DetectTlsVersionData *)ptr;
    SCFree(id_d);
}

#ifdef UNITTESTS
#include "tests/detect-tls-version.c"
#endif
