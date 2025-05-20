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
#include "threads.h"
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

#include "app-layer.h"
#include "app-layer-parser.h"

#include "app-layer-ssl.h"
#include "detect-tls-version.h"

#include "stream-tcp.h"

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
    sigmatch_table[DETECT_TLS_VERSION].name = "tls.version";
    sigmatch_table[DETECT_TLS_VERSION].desc = "match on TLS/SSL version";
    sigmatch_table[DETECT_TLS_VERSION].url = "/rules/tls-keywords.html#tls-version";
    sigmatch_table[DETECT_TLS_VERSION].AppLayerTxMatch = DetectTlsVersionMatch;
    sigmatch_table[DETECT_TLS_VERSION].Setup = DetectTlsVersionSetup;
    sigmatch_table[DETECT_TLS_VERSION].Free = DetectTlsVersionFree;
    sigmatch_table[DETECT_TLS_VERSION].flags = SIGMATCH_SUPPORT_FIREWALL;
#ifdef UNITTESTS
    sigmatch_table[DETECT_TLS_VERSION].RegisterTests = DetectTlsVersionRegisterTests;
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
    int res = 0;
    size_t pcre2len;

    pcre2_match_data *match = NULL;
    int ret = DetectParsePcreExec(&parse_regex, &match, str, 0, 0);
    if (ret < 1 || ret > 3) {
        SCLogError("invalid tls.version option");
        goto error;
    }

    if (ret > 1) {
        char ver_ptr[64];
        char *tmp_str;
        pcre2len = sizeof(ver_ptr);
        res = pcre2_substring_copy_bynumber(match, 1, (PCRE2_UCHAR8 *)ver_ptr, &pcre2len);
        if (res < 0) {
            SCLogError("pcre2_substring_copy_bynumber failed");
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
            SCLogError("Invalid value");
            goto error;
        }

        tls->ver = temp;

        SCLogDebug("will look for tls %"PRIu16"", tls->ver);
    }

    pcre2_match_data_free(match);
    return tls;

error:
    if (match) {
        pcre2_match_data_free(match);
    }
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

    if (SCDetectSignatureSetAppProto(s, ALPROTO_TLS) != 0)
        return -1;

    tls = DetectTlsVersionParse(de_ctx, str);
    if (tls == NULL)
        goto error;

    /* keyword supports multiple hooks, so attach to the hook specified in the rule. */
    int list = g_tls_generic_list_id;
    /* Okay so far so good, lets get this into a SigMatch
     * and put it in the Signature. */
    if (s->init_data->hook.type == SIGNATURE_HOOK_TYPE_APP) {
        list = s->init_data->hook.sm_list;
    }

    if (SCSigMatchAppendSMToList(de_ctx, s, DETECT_TLS_VERSION, (SigMatchCtx *)tls, list) == NULL) {
        goto error;
    }

    return 0;

error:
    if (tls != NULL)
        DetectTlsVersionFree(de_ctx, tls);
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
