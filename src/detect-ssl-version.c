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
 * \file   detect-ssl-version.c
 *
 * \author Gurvinder Singh <gurvindersinghdahiya@gmail.com>
 *
 * Implements the ssl_version keyword
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

#include "detect-ssl-version.h"

#include "stream-tcp.h"
#include "app-layer-ssl.h"


static int DetectSslVersionMatch(DetectEngineThreadCtx *,
        Flow *, uint8_t, void *, void *,
        const Signature *, const SigMatchCtx *);
static int DetectSslVersionSetup(DetectEngineCtx *, Signature *, const char *);
#ifdef UNITTESTS
static void DetectSslVersionRegisterTests(void);
#endif
static void DetectSslVersionFree(DetectEngineCtx *, void *);
static int g_tls_generic_list_id = 0;

/**
 * \brief Registration function for keyword: ssl_version
 */
void DetectSslVersionRegister(void)
{
    sigmatch_table[DETECT_AL_SSL_VERSION].name = "ssl_version";
    sigmatch_table[DETECT_AL_SSL_VERSION].desc = "match version of SSL/TLS record";
    sigmatch_table[DETECT_AL_SSL_VERSION].url = "/rules/tls-keywords.html#ssl-version";
    sigmatch_table[DETECT_AL_SSL_VERSION].AppLayerTxMatch = DetectSslVersionMatch;
    sigmatch_table[DETECT_AL_SSL_VERSION].Setup = DetectSslVersionSetup;
    sigmatch_table[DETECT_AL_SSL_VERSION].Free  = DetectSslVersionFree;
#ifdef UNITTESTS
    sigmatch_table[DETECT_AL_SSL_VERSION].RegisterTests = DetectSslVersionRegisterTests;
#endif

    g_tls_generic_list_id = DetectBufferTypeRegister("tls_generic");
}

/**
 * \brief match the specified version on a ssl session
 *
 * \param t pointer to thread vars
 * \param det_ctx pointer to the pattern matcher thread
 * \param p pointer to the current packet
 * \param m pointer to the sigmatch that we will cast into DetectSslVersionData
 *
 * \retval 0 no match
 * \retval 1 match
 */
static int DetectSslVersionMatch(DetectEngineThreadCtx *det_ctx,
        Flow *f, uint8_t flags, void *state, void *txv,
        const Signature *s, const SigMatchCtx *m)
{
    SCEnter();

    int ret = 0;
    uint16_t ver = 0;
    uint8_t sig_ver = TLS_UNKNOWN;

    const DetectSslVersionData *ssl = (const DetectSslVersionData *)m;
    SSLState *app_state = (SSLState *)state;
    if (app_state == NULL) {
        SCLogDebug("no app state, no match");
        SCReturnInt(0);
    }

    if (flags & STREAM_TOCLIENT) {
        SCLogDebug("server (toclient) version is 0x%02X",
                   app_state->server_connp.version);
        ver = app_state->server_connp.version;
    } else if (flags & STREAM_TOSERVER) {
        SCLogDebug("client (toserver) version is 0x%02X",
                   app_state->client_connp.version);
        ver = app_state->client_connp.version;
    }

    switch (ver) {
        case SSL_VERSION_2:
            if (ver == ssl->data[SSLv2].ver)
                ret = 1;
            sig_ver = SSLv2;
            break;
        case SSL_VERSION_3:
            if (ver == ssl->data[SSLv3].ver)
                ret = 1;
            sig_ver = SSLv3;
            break;
        case TLS_VERSION_10:
            if (ver == ssl->data[TLS10].ver)
                ret = 1;
            sig_ver = TLS10;
            break;
        case TLS_VERSION_11:
            if (ver == ssl->data[TLS11].ver)
                ret = 1;
            sig_ver = TLS11;
            break;
        case TLS_VERSION_12:
            if (ver == ssl->data[TLS12].ver)
                ret = 1;
            sig_ver = TLS12;
            break;
        case TLS_VERSION_13_DRAFT28:
        case TLS_VERSION_13_DRAFT27:
        case TLS_VERSION_13_DRAFT26:
        case TLS_VERSION_13_DRAFT25:
        case TLS_VERSION_13_DRAFT24:
        case TLS_VERSION_13_DRAFT23:
        case TLS_VERSION_13_DRAFT22:
        case TLS_VERSION_13_DRAFT21:
        case TLS_VERSION_13_DRAFT20:
        case TLS_VERSION_13_DRAFT19:
        case TLS_VERSION_13_DRAFT18:
        case TLS_VERSION_13_DRAFT17:
        case TLS_VERSION_13_DRAFT16:
        case TLS_VERSION_13_PRE_DRAFT16:
            if (((ver >> 8) & 0xff) == 0x7f)
                ver = TLS_VERSION_13;
            /* fall through */
        case TLS_VERSION_13:
            if (ver == ssl->data[TLS13].ver)
                ret = 1;
            sig_ver = TLS13;
            break;
    }

    if (sig_ver == TLS_UNKNOWN)
        SCReturnInt(0);

    SCReturnInt(ret ^ ((ssl->data[sig_ver].flags & DETECT_SSL_VERSION_NEGATED) ? 1 : 0));
}

struct SSLVersionKeywords {
    const char *word;
    int index;
    uint16_t value;
};

struct SSLVersionKeywords ssl_version_keywords[TLS_SIZE] = {
    { "sslv2", SSLv2, SSL_VERSION_2 },
    { "sslv3", SSLv3, SSL_VERSION_3 },
    { "tls1.0", TLS10, TLS_VERSION_10 },
    { "tls1.1", TLS11, TLS_VERSION_11 },
    { "tls1.2", TLS12, TLS_VERSION_12 },
    { "tls1.3", TLS13, TLS_VERSION_13 },
};

/**
 * \brief This function is used to parse ssl_version data passed via
 *        keyword: "ssl_version"
 *
 * \param de_ctx Pointer to the detection engine context
 * \param str Pointer to the user provided options
 *
 * \retval ssl pointer to DetectSslVersionData on success
 * \retval NULL on failure
 */
static DetectSslVersionData *DetectSslVersionParse(DetectEngineCtx *de_ctx, const char *str)
{
    DetectSslVersionData *ssl = NULL;
    const char *tmp_str = str;
    size_t tmp_len = 0;
    uint8_t found = 0;

    /* We have a correct ssl_version options */
    ssl = SCCalloc(1, sizeof(DetectSslVersionData));
    if (unlikely(ssl == NULL))
        goto error;

    // skip leading space
    while (tmp_str[0] != 0 && isspace(tmp_str[0])) {
        tmp_str++;
    }
    if (tmp_str[0] == 0) {
        SCLogError(SC_ERR_INVALID_VALUE, "Invalid empty value");
        goto error;
    }
    // iterate every version separated by comma
    while (tmp_str[0] != 0) {
        uint8_t neg = 0;
        if (tmp_str[0] == '!') {
            neg = 1;
            tmp_str++;
        }
        // counts word length
        tmp_len = 0;
        while (tmp_str[tmp_len] != 0 && !isspace(tmp_str[tmp_len]) && tmp_str[tmp_len] != ',') {
            tmp_len++;
        }

        bool is_keyword = false;
        for (size_t i = 0; i < TLS_SIZE; i++) {
            if (tmp_len == strlen(ssl_version_keywords[i].word) &&
                    strncasecmp(ssl_version_keywords[i].word, tmp_str, tmp_len) == 0) {
                if (ssl->data[ssl_version_keywords[i].index].ver != 0) {
                    SCLogError(SC_ERR_INVALID_VALUE, "Invalid duplicate value");
                    goto error;
                }
                ssl->data[ssl_version_keywords[i].index].ver = ssl_version_keywords[i].value;
                if (neg == 1)
                    ssl->data[ssl_version_keywords[i].index].flags |= DETECT_SSL_VERSION_NEGATED;
                is_keyword = true;
                break;
            }
        }
        if (!is_keyword) {
            SCLogError(SC_ERR_INVALID_VALUE, "Invalid unknown value");
            goto error;
        }

        /* check consistency between negative and positive values :
         * if there is a negative value, it overrides positive values
         */
        if (found == 0) {
            found |= 1 << neg;
        } else if (found != 1 << neg) {
            SCLogError(SC_ERR_INVALID_VALUE, "Invalid value mixing negative and positive forms");
            goto error;
        }

        tmp_str += tmp_len;
        while (isspace(tmp_str[0]) || tmp_str[0] == ',') {
            tmp_str++;
        }
    }

    return ssl;

error:
    if (ssl != NULL)
        DetectSslVersionFree(de_ctx, ssl);
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
static int DetectSslVersionSetup (DetectEngineCtx *de_ctx, Signature *s, const char *str)
{
    DetectSslVersionData *ssl = NULL;
    SigMatch *sm = NULL;

    if (DetectSignatureSetAppProto(s, ALPROTO_TLS) != 0)
        return -1;

    ssl = DetectSslVersionParse(de_ctx, str);
    if (ssl == NULL)
        goto error;

    /* Okay so far so good, lets get this into a SigMatch
     * and put it in the Signature. */
    sm = SigMatchAlloc();
    if (sm == NULL)
        goto error;

    sm->type = DETECT_AL_SSL_VERSION;
    sm->ctx = (void *)ssl;

    SigMatchAppendSMToList(s, sm, g_tls_generic_list_id);
    return 0;

error:
    if (ssl != NULL)
        DetectSslVersionFree(de_ctx, ssl);
    if (sm != NULL)
        SCFree(sm);
    return -1;
}

/**
 * \brief this function will free memory associated with DetectSslVersionData
 *
 * \param id_d pointer to DetectSslVersionData
 */
void DetectSslVersionFree(DetectEngineCtx *de_ctx, void *ptr)
{
    if (ptr != NULL)
        SCFree(ptr);
}

#ifdef UNITTESTS
#include "tests/detect-ssl-version.c"
#endif
