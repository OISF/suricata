/* Copyright (C) 2007-2016 Open Information Security Foundation
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

#include "app-layer.h"
#include "app-layer-parser.h"

#include "detect-ssl-version.h"

#include "stream-tcp.h"
#include "app-layer-ssl.h"

/**
 * \brief Regex for parsing "id" option, matching number or "number"
 */
#define PARSE_REGEX  "^\\s*(!?[A-z0-9.]+)\\s*,?\\s*(!?[A-z0-9.]+)?\\s*\\,?\\s*" \
        "(!?[A-z0-9.]+)?\\s*,?\\s*(!?[A-z0-9.]+)?\\s*,?\\s*(!?[A-z0-9.]+)?\\s*$"

static pcre *parse_regex;
static pcre_extra *parse_regex_study;

static int DetectSslVersionMatch(ThreadVars *, DetectEngineThreadCtx *,
        Flow *, uint8_t, void *, void *,
        const Signature *, const SigMatchCtx *);
static int DetectSslVersionSetup(DetectEngineCtx *, Signature *, const char *);
static void DetectSslVersionRegisterTests(void);
static void DetectSslVersionFree(void *);
static int g_tls_generic_list_id = 0;

/**
 * \brief Registration function for keyword: ssl_version
 */
void DetectSslVersionRegister(void)
{
    sigmatch_table[DETECT_AL_SSL_VERSION].name = "ssl_version";
    sigmatch_table[DETECT_AL_SSL_VERSION].AppLayerTxMatch = DetectSslVersionMatch;
    sigmatch_table[DETECT_AL_SSL_VERSION].Setup = DetectSslVersionSetup;
    sigmatch_table[DETECT_AL_SSL_VERSION].Free  = DetectSslVersionFree;
    sigmatch_table[DETECT_AL_SSL_VERSION].RegisterTests = DetectSslVersionRegisterTests;

    DetectSetupParseRegexes(PARSE_REGEX, &parse_regex, &parse_regex_study);

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
static int DetectSslVersionMatch(ThreadVars *t, DetectEngineThreadCtx *det_ctx,
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
    }

    if (sig_ver == TLS_UNKNOWN)
        SCReturnInt(0);

    SCReturnInt(ret ^ ((ssl->data[sig_ver].flags & DETECT_SSL_VERSION_NEGATED) ? 1 : 0));
}

/**
 * \brief This function is used to parse ssl_version data passed via
 *        keyword: "ssl_version"
 *
 * \param str Pointer to the user provided options
 *
 * \retval ssl pointer to DetectSslVersionData on success
 * \retval NULL on failure
 */
static DetectSslVersionData *DetectSslVersionParse(const char *str)
{
    DetectSslVersionData *ssl = NULL;
	#define MAX_SUBSTRINGS 30
    int ret = 0, res = 0;
    int ov[MAX_SUBSTRINGS];

    ret = pcre_exec(parse_regex, parse_regex_study, str, strlen(str), 0, 0,
                    ov, MAX_SUBSTRINGS);

    if (ret < 1 || ret > 5) {
        SCLogError(SC_ERR_PCRE_MATCH, "invalid ssl_version option");
        goto error;
    }

    if (ret > 1) {
        const char *str_ptr;
        char *orig;
        uint8_t found = 0, neg = 0;
        char *tmp_str;

        /* We have a correct ssl_version options */
        ssl = SCCalloc(1, sizeof (DetectSslVersionData));
        if (unlikely(ssl == NULL))
            goto error;

        int i;
        for (i = 1; i < ret; i++) {
            res = pcre_get_substring((char *) str, ov, MAX_SUBSTRINGS, i, &str_ptr);
            if (res < 0) {
                SCLogError(SC_ERR_PCRE_GET_SUBSTRING, "pcre_get_substring failed");
                if (found == 0)
                    goto error;
                break;
            }

            orig = SCStrdup((char*) str_ptr);
            if (unlikely(orig == NULL)) {
                goto error;
            }
            tmp_str = orig;

            /* Let's see if we need to scape "'s */
            if (tmp_str[0] == '"') {
                tmp_str[strlen(tmp_str) - 1] = '\0';
                tmp_str += 1;
            }


            if (tmp_str[0] == '!') {
                neg = 1;
                tmp_str++;
            }

            if (strncasecmp("sslv2", tmp_str, 5) == 0) {
                ssl->data[SSLv2].ver = SSL_VERSION_2;
                if (neg == 1)
                    ssl->data[SSLv2].flags |= DETECT_SSL_VERSION_NEGATED;
            } else if (strncasecmp("sslv3", tmp_str, 5) == 0) {
                ssl->data[SSLv3].ver = SSL_VERSION_3;
                if (neg == 1)
                    ssl->data[SSLv3].flags |= DETECT_SSL_VERSION_NEGATED;
            } else if (strncasecmp("tls1.0", tmp_str, 6) == 0) {
                ssl->data[TLS10].ver = TLS_VERSION_10;
                if (neg == 1)
                    ssl->data[TLS10].flags |= DETECT_SSL_VERSION_NEGATED;
            } else if (strncasecmp("tls1.1", tmp_str, 6) == 0) {
                ssl->data[TLS11].ver = TLS_VERSION_11;
                if (neg == 1)
                    ssl->data[TLS11].flags |= DETECT_SSL_VERSION_NEGATED;
            } else if (strncasecmp("tls1.2", tmp_str, 6) == 0) {
                ssl->data[TLS12].ver = TLS_VERSION_12;
                if (neg == 1)
                    ssl->data[TLS12].flags |= DETECT_SSL_VERSION_NEGATED;
            }  else if (strcmp(tmp_str, "") == 0) {
                SCFree(orig);
                if (found == 0)
                    goto error;
                break;
            } else {
                SCLogError(SC_ERR_INVALID_VALUE, "Invalid value");
                SCFree(orig);
                goto error;
            }

            found = 1;
            neg = 0;
            SCFree(orig);
            pcre_free_substring(str_ptr);
        }
    }

    return ssl;

error:
    if (ssl != NULL)
        DetectSslVersionFree(ssl);
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

    ssl = DetectSslVersionParse(str);
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
        DetectSslVersionFree(ssl);
    if (sm != NULL)
        SCFree(sm);
    return -1;
}

/**
 * \brief this function will free memory associated with DetectSslVersionData
 *
 * \param id_d pointer to DetectSslVersionData
 */
void DetectSslVersionFree(void *ptr)
{
    if (ptr != NULL)
        SCFree(ptr);
}

/**********************************Unittests***********************************/

#ifdef UNITTESTS /* UNITTESTS */

/**
 * \test DetectSslVersionTestParse01 is a test to make sure that we parse the
 *      "ssl_version" option correctly when given valid ssl_version option
 */
static int DetectSslVersionTestParse01(void)
{
    DetectSslVersionData *ssl = NULL;
    ssl = DetectSslVersionParse("SSlv3");
    FAIL_IF_NULL(ssl);
    FAIL_IF_NOT(ssl->data[SSLv3].ver == SSL_VERSION_3);
    DetectSslVersionFree(ssl);
    PASS;
}

/**
 * \test DetectSslVersionTestParse02 is a test to make sure that we parse the
 *      "ssl_version" option correctly when given an invalid ssl_version option
 *       it should return ssl = NULL
 */
static int DetectSslVersionTestParse02(void)
{
    DetectSslVersionData *ssl = NULL;
    ssl = DetectSslVersionParse("2.5");
    FAIL_IF_NOT_NULL(ssl);
    DetectSslVersionFree(ssl);
    PASS;
}

/**
 * \test DetectSslVersionTestParse03 is a test to make sure that we parse the
 *      "ssl_version" options correctly when given valid ssl_version options
 */
static int DetectSslVersionTestParse03(void)
{
    DetectSslVersionData *ssl = NULL;
    ssl = DetectSslVersionParse("SSlv3,tls1.0, !tls1.2");
    FAIL_IF_NULL(ssl);
    FAIL_IF_NOT(ssl->data[SSLv3].ver == SSL_VERSION_3);
    FAIL_IF_NOT(ssl->data[TLS10].ver == TLS_VERSION_10);
    FAIL_IF_NOT(ssl->data[TLS12].ver == TLS_VERSION_12);
    FAIL_IF_NOT(ssl->data[TLS12].flags & DETECT_SSL_VERSION_NEGATED);
    DetectSslVersionFree(ssl);
    PASS;
}

#include "stream-tcp-reassemble.h"

/** \test Send a get request in three chunks + more data. */
static int DetectSslVersionTestDetect01(void)
{
    Flow f;
    uint8_t sslbuf1[] = { 0x16 };
    uint32_t ssllen1 = sizeof(sslbuf1);
    uint8_t sslbuf2[] = { 0x03 };
    uint32_t ssllen2 = sizeof(sslbuf2);
    uint8_t sslbuf3[] = { 0x01 };
    uint32_t ssllen3 = sizeof(sslbuf3);
    uint8_t sslbuf4[] = { 0x01, 0x00, 0x00, 0xad, 0x03, 0x01 };
    uint32_t ssllen4 = sizeof(sslbuf4);
    TcpSession ssn;
    Packet *p = NULL;
    Signature *s = NULL;
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx = NULL;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&th_v, 0, sizeof(th_v));
    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    p = UTHBuildPacket(NULL, 0, IPPROTO_TCP);

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;
    p->flow = &f;
    p->flowflags |= FLOW_PKT_TOSERVER;
    p->flowflags |= FLOW_PKT_ESTABLISHED;
    p->flags |= PKT_HAS_FLOW | PKT_STREAM_EST;
    f.alproto = ALPROTO_TLS;

    StreamTcpInitConfig(TRUE);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);

    de_ctx->flags |= DE_QUIET;

    s = de_ctx->sig_list = SigInit(de_ctx,"alert tls any any -> any any (msg:\"TLS\"; ssl_version:tls1.0; sid:1;)");
    FAIL_IF_NULL(s);

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    FLOWLOCK_WRLOCK(&f);
    int r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_TLS,
                                STREAM_TOSERVER, sslbuf1, ssllen1);
    FAIL_IF(r != 0);

    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_TLS, STREAM_TOSERVER,
                            sslbuf2, ssllen2);
    FAIL_IF(r != 0);

    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_TLS, STREAM_TOSERVER,
                            sslbuf3, ssllen3);
    FAIL_IF(r != 0);

    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_TLS, STREAM_TOSERVER,
                            sslbuf4, ssllen4);
    FAIL_IF(r != 0);
    FLOWLOCK_UNLOCK(&f);

    SSLState *app_state = f.alstate;
    FAIL_IF_NULL(app_state);

    FAIL_IF(app_state->client_connp.content_type != 0x16);

    FAIL_IF(app_state->client_connp.version != TLS_VERSION_10);

    SCLogDebug("app_state is at %p, app_state->server_connp.version 0x%02X app_state->client_connp.version 0x%02X",
        app_state, app_state->server_connp.version, app_state->client_connp.version);

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);

    FAIL_IF_NOT(PacketAlertCheck(p, 1));

    AppLayerParserThreadCtxFree(alp_tctx);
    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);

    StreamTcpFreeConfig(TRUE);
    FLOW_DESTROY(&f);

    UTHFreePackets(&p, 1);

    PASS;
}

static int DetectSslVersionTestDetect02(void)
{
    Flow f;
    uint8_t sslbuf1[] = { 0x16 };
    uint32_t ssllen1 = sizeof(sslbuf1);
    uint8_t sslbuf2[] = { 0x03 };
    uint32_t ssllen2 = sizeof(sslbuf2);
    uint8_t sslbuf3[] = { 0x01 };
    uint32_t ssllen3 = sizeof(sslbuf3);
    uint8_t sslbuf4[] = { 0x01, 0x00, 0x00, 0xad, 0x03, 0x02 };
    uint32_t ssllen4 = sizeof(sslbuf4);
    TcpSession ssn;
    Packet *p = NULL;
    Signature *s = NULL;
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx = NULL;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&th_v, 0, sizeof(th_v));
    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    p = UTHBuildPacket(NULL, 0, IPPROTO_TCP);

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;
    p->flow = &f;
    p->flowflags |= FLOW_PKT_TOSERVER;
    p->flowflags |= FLOW_PKT_ESTABLISHED;
    p->flags |= PKT_HAS_FLOW | PKT_STREAM_EST;
    f.alproto = ALPROTO_TLS;

    StreamTcpInitConfig(TRUE);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);

    de_ctx->flags |= DE_QUIET;

    s = de_ctx->sig_list = SigInit(de_ctx,"alert tls any any -> any any (msg:\"TLS\"; ssl_version:tls1.0; sid:1;)");
    FAIL_IF_NULL(s);

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    FLOWLOCK_WRLOCK(&f);
    int r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_TLS,
                                STREAM_TOSERVER, sslbuf1, ssllen1);
    FAIL_IF(r != 0);

    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_TLS, STREAM_TOSERVER,
                            sslbuf2, ssllen2);
    FAIL_IF(r != 0);

    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_TLS, STREAM_TOSERVER,
                            sslbuf3, ssllen3);
    FAIL_IF(r != 0);

    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_TLS, STREAM_TOSERVER,
                            sslbuf4, ssllen4);
    FAIL_IF(r != 0);
    FLOWLOCK_UNLOCK(&f);

    SSLState *app_state = f.alstate;
    FAIL_IF_NULL(app_state);

    FAIL_IF(app_state->client_connp.content_type != 0x16);

    FAIL_IF(app_state->client_connp.version != TLS_VERSION_10);

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);

    FAIL_IF_NOT(PacketAlertCheck(p, 1));

    AppLayerParserThreadCtxFree(alp_tctx);
    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);
    StreamTcpFreeConfig(TRUE);
    FLOW_DESTROY(&f);
    UTHFreePackets(&p, 1);

    PASS;
}

#endif /* UNITTESTS */

/**
 * \brief this function registers unit tests for DetectSslVersion
 */
static void DetectSslVersionRegisterTests(void)
{
#ifdef UNITTESTS /* UNITTESTS */
    UtRegisterTest("DetectSslVersionTestParse01", DetectSslVersionTestParse01);
    UtRegisterTest("DetectSslVersionTestParse02", DetectSslVersionTestParse02);
    UtRegisterTest("DetectSslVersionTestParse03", DetectSslVersionTestParse03);
    UtRegisterTest("DetectSslVersionTestDetect01",
                   DetectSslVersionTestDetect01);
    UtRegisterTest("DetectSslVersionTestDetect02",
                   DetectSslVersionTestDetect02);
#endif /* UNITTESTS */

    return;
}
