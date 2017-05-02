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
 * \file
 *
 * \author Victor Julien <victor@inliniac.net>
 *
 * Implements the tls.version keyword
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

#include "app-layer-ssl.h"
#include "detect-tls-version.h"

#include "stream-tcp.h"

/**
 * \brief Regex for parsing "id" option, matching number or "number"
 */
#define PARSE_REGEX  "^\\s*([A-z0-9\\.]+|\"[A-z0-9\\.]+\")\\s*$"

static pcre *parse_regex;
static pcre_extra *parse_regex_study;

static int DetectTlsVersionMatch (ThreadVars *, DetectEngineThreadCtx *,
        Flow *, uint8_t, void *, void *,
        const Signature *, const SigMatchCtx *);
static int DetectTlsVersionSetup (DetectEngineCtx *, Signature *, const char *);
static void DetectTlsVersionRegisterTests(void);
static void DetectTlsVersionFree(void *);
static int g_tls_generic_list_id = 0;

/**
 * \brief Registration function for keyword: tls.version
 */
void DetectTlsVersionRegister (void)
{
    sigmatch_table[DETECT_AL_TLS_VERSION].name = "tls.version";
    sigmatch_table[DETECT_AL_TLS_VERSION].desc = "match on TLS/SSL version";
    sigmatch_table[DETECT_AL_TLS_VERSION].url = DOC_URL DOC_VERSION "/rules/tls-keywords.html#tlsversion";
    sigmatch_table[DETECT_AL_TLS_VERSION].AppLayerTxMatch = DetectTlsVersionMatch;
    sigmatch_table[DETECT_AL_TLS_VERSION].Setup = DetectTlsVersionSetup;
    sigmatch_table[DETECT_AL_TLS_VERSION].Free  = DetectTlsVersionFree;
    sigmatch_table[DETECT_AL_TLS_VERSION].RegisterTests = DetectTlsVersionRegisterTests;

    DetectSetupParseRegexes(PARSE_REGEX, &parse_regex, &parse_regex_study);

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
static int DetectTlsVersionMatch (ThreadVars *t, DetectEngineThreadCtx *det_ctx,
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
    SCLogDebug("looking for tls_data->ver 0x%02X (flags 0x%02X)", tls_data->ver, flags);

    if (flags & STREAM_TOCLIENT) {
        SCLogDebug("server (toclient) version is 0x%02X", ssl_state->server_connp.version);
        if (tls_data->ver == ssl_state->server_connp.version)
            ret = 1;
    } else if (flags & STREAM_TOSERVER) {
        SCLogDebug("client (toserver) version is 0x%02X", ssl_state->client_connp.version);
        if (tls_data->ver == ssl_state->client_connp.version)
            ret = 1;
    }

    SCReturnInt(ret);
}

/**
 * \brief This function is used to parse IPV4 ip_id passed via keyword: "id"
 *
 * \param idstr Pointer to the user provided id option
 *
 * \retval id_d pointer to DetectTlsVersionData on success
 * \retval NULL on failure
 */
static DetectTlsVersionData *DetectTlsVersionParse (const char *str)
{
    uint16_t temp;
    DetectTlsVersionData *tls = NULL;
	#define MAX_SUBSTRINGS 30
    int ret = 0, res = 0;
    int ov[MAX_SUBSTRINGS];

    ret = pcre_exec(parse_regex, parse_regex_study, str, strlen(str), 0, 0,
                    ov, MAX_SUBSTRINGS);

    if (ret < 1 || ret > 3) {
        SCLogError(SC_ERR_PCRE_MATCH, "invalid tls.version option");
        goto error;
    }

    if (ret > 1) {
        const char *str_ptr;
        char *orig;
        char *tmp_str;
        res = pcre_get_substring((char *)str, ov, MAX_SUBSTRINGS, 1, &str_ptr);
        if (res < 0) {
            SCLogError(SC_ERR_PCRE_GET_SUBSTRING, "pcre_get_substring failed");
            goto error;
        }

        /* We have a correct id option */
        tls = SCMalloc(sizeof(DetectTlsVersionData));
        if (unlikely(tls == NULL))
            goto error;

        orig = SCStrdup((char*)str_ptr);
        if (unlikely(orig == NULL)) {
            goto error;
        }
        tmp_str=orig;

        /* Let's see if we need to scape "'s */
        if (tmp_str[0] == '"')
        {
            tmp_str[strlen(tmp_str) - 1] = '\0';
            tmp_str += 1;
        }

        if (strcmp("1.0", tmp_str) == 0) {
            temp = TLS_VERSION_10;
        } else if (strcmp("1.1", tmp_str) == 0) {
            temp = TLS_VERSION_11;
        } else if (strcmp("1.2", tmp_str) == 0) {
            temp = TLS_VERSION_12;
        } else {
            SCLogError(SC_ERR_INVALID_VALUE, "Invalid value");
            SCFree(orig);
            goto error;
        }

        tls->ver = temp;

        SCFree(orig);

        SCLogDebug("will look for tls %"PRIu8"", tls->ver);
    }

    return tls;

error:
    if (tls != NULL)
        DetectTlsVersionFree(tls);
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

    tls = DetectTlsVersionParse(str);
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
        DetectTlsVersionFree(tls);
    if (sm != NULL)
        SCFree(sm);
    return -1;

}

/**
 * \brief this function will free memory associated with DetectTlsVersionData
 *
 * \param id_d pointer to DetectTlsVersionData
 */
static void DetectTlsVersionFree(void *ptr)
{
    DetectTlsVersionData *id_d = (DetectTlsVersionData *)ptr;
    SCFree(id_d);
}

#ifdef UNITTESTS /* UNITTESTS */

/**
 * \test DetectTlsVersionTestParse01 is a test to make sure that we parse the "id"
 *       option correctly when given valid id option
 */
static int DetectTlsVersionTestParse01 (void)
{
    DetectTlsVersionData *tls = NULL;
    tls = DetectTlsVersionParse("1.0");
    FAIL_IF_NULL(tls);
    FAIL_IF_NOT(tls->ver == TLS_VERSION_10);
    DetectTlsVersionFree(tls);
    PASS;
}

/**
 * \test DetectTlsVersionTestParse02 is a test to make sure that we parse the "id"
 *       option correctly when given an invalid id option
 *       it should return id_d = NULL
 */
static int DetectTlsVersionTestParse02 (void)
{
    DetectTlsVersionData *tls = NULL;
    tls = DetectTlsVersionParse("2.5");
    FAIL_IF_NOT_NULL(tls);
    DetectTlsVersionFree(tls);
    PASS;
}

#include "stream-tcp-reassemble.h"

/** \test Send a get request in three chunks + more data. */
static int DetectTlsVersionTestDetect01(void)
{
    Flow f;
    uint8_t tlsbuf1[] = { 0x16 };
    uint32_t tlslen1 = sizeof(tlsbuf1);
    uint8_t tlsbuf2[] = { 0x03 };
    uint32_t tlslen2 = sizeof(tlsbuf2);
    uint8_t tlsbuf3[] = { 0x01 };
    uint32_t tlslen3 = sizeof(tlsbuf3);
    uint8_t tlsbuf4[] = { 0x01, 0x00, 0x00, 0xad, 0x03, 0x01 };
    uint32_t tlslen4 = sizeof(tlsbuf4);
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
    p->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    f.alproto = ALPROTO_TLS;

    StreamTcpInitConfig(TRUE);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);

    de_ctx->flags |= DE_QUIET;

    s = de_ctx->sig_list = SigInit(de_ctx,"alert tls any any -> any any (msg:\"TLS\"; tls.version:1.0; sid:1;)");
    FAIL_IF_NULL(s);

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    FLOWLOCK_WRLOCK(&f);
    int r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_TLS,
                                STREAM_TOSERVER, tlsbuf1, tlslen1);
    FAIL_IF(r != 0);

    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_TLS, STREAM_TOSERVER,
                            tlsbuf2, tlslen2);
    FAIL_IF(r != 0);

    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_TLS, STREAM_TOSERVER,
                            tlsbuf3, tlslen3);
    FAIL_IF(r != 0);

    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_TLS, STREAM_TOSERVER,
                            tlsbuf4, tlslen4);
    FAIL_IF(r != 0);
    FLOWLOCK_UNLOCK(&f);

    SSLState *ssl_state = f.alstate;
    FAIL_IF_NULL(ssl_state);

    FAIL_IF(ssl_state->client_connp.content_type != 0x16);

    FAIL_IF(ssl_state->client_connp.version != TLS_VERSION_10);

    SCLogDebug("ssl_state is at %p, ssl_state->server_version 0x%02X "
               "ssl_state->client_version 0x%02X",
               ssl_state, ssl_state->server_connp.version,
               ssl_state->client_connp.version);

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);

    FAIL_IF_NOT(PacketAlertCheck(p, 1));

    AppLayerParserThreadCtxFree(alp_tctx);
    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);

    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);

    StreamTcpFreeConfig(TRUE);
    FLOW_DESTROY(&f);

    UTHFreePackets(&p, 1);

    PASS;
}

static int DetectTlsVersionTestDetect02(void)
{
    Flow f;
    uint8_t tlsbuf1[] = { 0x16 };
    uint32_t tlslen1 = sizeof(tlsbuf1);
    uint8_t tlsbuf2[] = { 0x03 };
    uint32_t tlslen2 = sizeof(tlsbuf2);
    uint8_t tlsbuf3[] = { 0x01 };
    uint32_t tlslen3 = sizeof(tlsbuf3);
    uint8_t tlsbuf4[] = { 0x01, 0x00, 0x00, 0xad, 0x03, 0x02 };
    uint32_t tlslen4 = sizeof(tlsbuf4);
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
    p->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    f.alproto = ALPROTO_TLS;

    StreamTcpInitConfig(TRUE);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);

    de_ctx->flags |= DE_QUIET;

    s = de_ctx->sig_list = SigInit(de_ctx,"alert tls any any -> any any (msg:\"TLS\"; tls.version:1.0; sid:1;)");
    FAIL_IF_NULL(s);

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    FLOWLOCK_WRLOCK(&f);
    int r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_TLS,
                                STREAM_TOSERVER, tlsbuf1, tlslen1);
    FAIL_IF(r != 0);

    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_TLS, STREAM_TOSERVER,
                            tlsbuf2, tlslen2);
    FAIL_IF(r != 0);

    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_TLS, STREAM_TOSERVER,
                            tlsbuf3, tlslen3);
    FAIL_IF(r != 0);

    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_TLS, STREAM_TOSERVER,
                            tlsbuf4, tlslen4);
    FAIL_IF(r != 0);
    FLOWLOCK_UNLOCK(&f);

    SSLState *ssl_state = f.alstate;
    FAIL_IF_NULL(ssl_state);

    FAIL_IF(ssl_state->client_connp.content_type != 0x16);

    FAIL_IF(ssl_state->client_connp.version != TLS_VERSION_10);

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);

    FAIL_IF_NOT(PacketAlertCheck(p, 1));

    AppLayerParserThreadCtxFree(alp_tctx);
    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);

    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);

    StreamTcpFreeConfig(TRUE);
    FLOW_DESTROY(&f);

    UTHFreePackets(&p, 1);

    PASS;
}
#endif /* UNITTESTS */

/**
 * \brief this function registers unit tests for DetectTlsVersion
 */
static void DetectTlsVersionRegisterTests(void)
{
#ifdef UNITTESTS /* UNITTESTS */
    UtRegisterTest("DetectTlsVersionTestParse01", DetectTlsVersionTestParse01);
    UtRegisterTest("DetectTlsVersionTestParse02", DetectTlsVersionTestParse02);
    UtRegisterTest("DetectTlsVersionTestDetect01",
                   DetectTlsVersionTestDetect01);
    UtRegisterTest("DetectTlsVersionTestDetect02",
                   DetectTlsVersionTestDetect02);
#endif /* UNITTESTS */
}

