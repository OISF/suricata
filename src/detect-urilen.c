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
 * \author Gurvinder Singh <gurvindersighdahiya@gmail.com>
 *
 * Implements the urilen keyword
 */

#include "suricata-common.h"
#include "app-layer.h"
#include "app-layer-protos.h"
#include "app-layer-htp.h"
#include "util-unittest.h"
#include "util-unittest-helper.h"

#include "detect.h"
#include "detect-parse.h"
#include "detect-engine.h"
#include "detect-engine-state.h"
#include "detect-content.h"

#include "detect-urilen.h"
#include "util-debug.h"
#include "util-byte.h"
#include "flow-util.h"
#include "stream-tcp.h"

/**
 * \brief Regex for parsing our urilen
 */
#define PARSE_REGEX  "^(?:\\s*)(<|>)?(?:\\s*)([0-9]{1,5})(?:\\s*)(?:(<>)(?:\\s*)([0-9]{1,5}))?\\s*(?:,\\s*(norm|raw))?\\s*$"

static DetectParseRegex parse_regex;

/*prototypes*/
static int DetectUrilenSetup (DetectEngineCtx *, Signature *, const char *);
static void DetectUrilenFree (DetectEngineCtx *, void *);
#ifdef UNITTESTS
static void DetectUrilenRegisterTests (void);
#endif
static int g_http_uri_buffer_id = 0;
static int g_http_raw_uri_buffer_id = 0;

/**
 * \brief Registration function for urilen: keyword
 */

void DetectUrilenRegister(void)
{
    sigmatch_table[DETECT_AL_URILEN].name = "urilen";
    sigmatch_table[DETECT_AL_URILEN].desc = "match on the length of the HTTP uri";
    sigmatch_table[DETECT_AL_URILEN].url = "/rules/http-keywords.html#urilen";
    sigmatch_table[DETECT_AL_URILEN].Match = NULL;
    sigmatch_table[DETECT_AL_URILEN].Setup = DetectUrilenSetup;
    sigmatch_table[DETECT_AL_URILEN].Free = DetectUrilenFree;
#ifdef UNITTESTS
    sigmatch_table[DETECT_AL_URILEN].RegisterTests = DetectUrilenRegisterTests;
#endif
    DetectSetupParseRegexes(PARSE_REGEX, &parse_regex);

    g_http_uri_buffer_id = DetectBufferTypeRegister("http_uri");
    g_http_raw_uri_buffer_id = DetectBufferTypeRegister("http_raw_uri");
}

/**
 * \brief This function is used to parse urilen options passed via urilen: keyword
 *
 * \param urilenstr Pointer to the user provided urilen options
 *
 * \retval urilend pointer to DetectUrilenData on success
 * \retval NULL on failure
 */

static DetectUrilenData *DetectUrilenParse (const char *urilenstr)
{
    DetectUrilenData *urilend = NULL;
    char *arg1 = NULL;
    char *arg2 = NULL;
    char *arg3 = NULL;
    char *arg4 = NULL;
    char *arg5 = NULL;
    int ret = 0, res = 0;
    size_t pcre2_len;

    ret = DetectParsePcreExec(&parse_regex, urilenstr, 0, 0);
    if (ret < 3 || ret > 6) {
        SCLogError(SC_ERR_PCRE_PARSE, "urilen option pcre parse error: \"%s\"", urilenstr);
        goto error;
    }
    const char *str_ptr;

    SCLogDebug("ret %d", ret);

    res = SC_Pcre2SubstringGet(parse_regex.match, 1, (PCRE2_UCHAR8 **)&str_ptr, &pcre2_len);
    if (res < 0) {
        SCLogError(SC_ERR_PCRE_GET_SUBSTRING, "pcre2_substring_get_bynumber failed");
        goto error;
    }
    arg1 = (char *) str_ptr;
    SCLogDebug("Arg1 \"%s\"", arg1);

    res = pcre2_substring_get_bynumber(parse_regex.match, 2, (PCRE2_UCHAR8 **)&str_ptr, &pcre2_len);
    if (res < 0) {
        SCLogError(SC_ERR_PCRE_GET_SUBSTRING, "pcre2_substring_get_bynumber failed");
        goto error;
    }
    arg2 = (char *) str_ptr;
    SCLogDebug("Arg2 \"%s\"", arg2);

    if (ret > 3) {
        res = SC_Pcre2SubstringGet(parse_regex.match, 3, (PCRE2_UCHAR8 **)&str_ptr, &pcre2_len);
        if (res < 0) {
            SCLogError(SC_ERR_PCRE_GET_SUBSTRING, "pcre2_substring_get_bynumber failed");
            goto error;
        }
        arg3 = (char *) str_ptr;
        SCLogDebug("Arg3 \"%s\"", arg3);

        if (ret > 4) {
            res = SC_Pcre2SubstringGet(parse_regex.match, 4, (PCRE2_UCHAR8 **)&str_ptr, &pcre2_len);
            if (res < 0) {
                SCLogError(SC_ERR_PCRE_GET_SUBSTRING, "pcre2_substring_get_bynumber failed");
                goto error;
            }
            arg4 = (char *) str_ptr;
            SCLogDebug("Arg4 \"%s\"", arg4);
        }
        if (ret > 5) {
            res = pcre2_substring_get_bynumber(
                    parse_regex.match, 5, (PCRE2_UCHAR8 **)&str_ptr, &pcre2_len);
            if (res < 0) {
                SCLogError(SC_ERR_PCRE_GET_SUBSTRING, "pcre2_substring_get_bynumber failed");
                goto error;
            }
            arg5 = (char *) str_ptr;
            SCLogDebug("Arg5 \"%s\"", arg5);
        }
    }

    urilend = SCMalloc(sizeof (DetectUrilenData));
    if (unlikely(urilend == NULL))
        goto error;
    memset(urilend, 0, sizeof(DetectUrilenData));

    if (arg1 != NULL && arg1[0] == '<')
        urilend->mode = DETECT_URILEN_LT;
    else if (arg1 != NULL && arg1[0] == '>')
        urilend->mode = DETECT_URILEN_GT;
    else
        urilend->mode = DETECT_URILEN_EQ;

    if (arg3 != NULL && strcmp("<>", arg3) == 0) {
        if (arg1 != NULL && strlen(arg1) != 0) {
            SCLogError(SC_ERR_INVALID_ARGUMENT,"Range specified but mode also set");
            goto error;
        }
        urilend->mode = DETECT_URILEN_RA;
    }

    /** set the first urilen value */
    if (StringParseUint16(&urilend->urilen1,10,strlen(arg2),arg2) <= 0){
        SCLogError(SC_ERR_INVALID_ARGUMENT,"Invalid size :\"%s\"",arg2);
        goto error;
    }

    /** set the second urilen value if specified */
    if (arg4 != NULL && strlen(arg4) > 0) {
        if (urilend->mode != DETECT_URILEN_RA) {
            SCLogError(SC_ERR_INVALID_ARGUMENT,"Multiple urilen values specified"
                                           " but mode is not range");
            goto error;
        }

        if(StringParseUint16(&urilend->urilen2,10,strlen(arg4),arg4) <= 0)
        {
            SCLogError(SC_ERR_INVALID_ARGUMENT,"Invalid size :\"%s\"",arg4);
            goto error;
        }

        if (urilend->urilen2 <= urilend->urilen1){
            SCLogError(SC_ERR_INVALID_ARGUMENT,"urilen2:%"PRIu16" <= urilen:"
                        "%"PRIu16"",urilend->urilen2,urilend->urilen1);
            goto error;
        }
    }

    if (arg5 != NULL) {
        if (strcasecmp("raw", arg5) == 0) {
            urilend->raw_buffer = 1;
        }
    }

    if (arg1 != NULL)
        pcre2_substring_free((PCRE2_UCHAR *)arg1);
    pcre2_substring_free((PCRE2_UCHAR *)arg2);
    if (arg3 != NULL)
        pcre2_substring_free((PCRE2_UCHAR *)arg3);
    if (arg4 != NULL)
        pcre2_substring_free((PCRE2_UCHAR *)arg4);
    if (arg5 != NULL)
        pcre2_substring_free((PCRE2_UCHAR *)arg5);
    return urilend;

error:
    if (urilend)
        SCFree(urilend);
    if (arg1 != NULL)
        pcre2_substring_free((PCRE2_UCHAR *)arg1);
    if (arg2 != NULL)
        pcre2_substring_free((PCRE2_UCHAR *)arg2);
    if (arg3 != NULL)
        pcre2_substring_free((PCRE2_UCHAR *)arg3);
    if (arg4 != NULL)
        pcre2_substring_free((PCRE2_UCHAR *)arg4);
    if (arg5 != NULL)
        pcre2_substring_free((PCRE2_UCHAR *)arg5);
    return NULL;
}

/**
 * \brief this function is used to parse urilen data into the current signature
 *
 * \param de_ctx pointer to the Detection Engine Context
 * \param s pointer to the Current Signature
 * \param urilenstr pointer to the user provided urilen options
 *
 * \retval 0 on Success
 * \retval -1 on Failure
 */
static int DetectUrilenSetup (DetectEngineCtx *de_ctx, Signature *s, const char *urilenstr)
{
    SCEnter();
    DetectUrilenData *urilend = NULL;
    SigMatch *sm = NULL;

    if (DetectSignatureSetAppProto(s, ALPROTO_HTTP1) != 0)
        return -1;

    urilend = DetectUrilenParse(urilenstr);
    if (urilend == NULL)
        goto error;
    sm = SigMatchAlloc();
    if (sm == NULL)
        goto error;
    sm->type = DETECT_AL_URILEN;
    sm->ctx = (void *)urilend;

    if (urilend->raw_buffer)
        SigMatchAppendSMToList(s, sm, g_http_raw_uri_buffer_id);
    else
        SigMatchAppendSMToList(s, sm, g_http_uri_buffer_id);

    SCReturnInt(0);

error:
    DetectUrilenFree(de_ctx, urilend);
    SCReturnInt(-1);
}

/**
 * \brief this function will free memory associated with DetectUrilenData
 *
 * \param ptr pointer to DetectUrilenData
 */
static void DetectUrilenFree(DetectEngineCtx *de_ctx, void *ptr)
{
    if (ptr == NULL)
        return;

    DetectUrilenData *urilend = (DetectUrilenData *)ptr;
    SCFree(urilend);
}

/** \brief set prefilter dsize pair
 *  \param s signature to get dsize value from
 */
void DetectUrilenApplyToContent(Signature *s, int list)
{
    uint16_t high = 65535;
    bool found = false;

    SigMatch *sm = s->init_data->smlists[list];
    for ( ; sm != NULL; sm = sm->next) {
        if (sm->type != DETECT_AL_URILEN)
            continue;

        DetectUrilenData *dd = (DetectUrilenData *)sm->ctx;

        switch (dd->mode) {
            case DETECT_URILEN_LT:
                high = dd->urilen1 + 1;
                break;
            case DETECT_URILEN_EQ:
                high = dd->urilen1;
                break;
            case DETECT_URILEN_RA:
                high = dd->urilen2 + 1;
                break;
            case DETECT_URILEN_GT:
                high = 65535;
                break;
        }
        found = true;
    }

    // skip 65535 to avoid mismatch on uri > 64k
    if (!found || high == 65535)
        return;

    SCLogDebug("high %u", high);

    sm = s->init_data->smlists[list];
    for ( ; sm != NULL;  sm = sm->next) {
        if (sm->type != DETECT_CONTENT) {
            continue;
        }
        DetectContentData *cd = (DetectContentData *)sm->ctx;
        if (cd == NULL) {
            continue;
        }

        if (cd->depth == 0 || cd->depth > high) {
            cd->depth = (uint16_t)high;
            SCLogDebug("updated %u, content %u to have depth %u "
                    "because of urilen.", s->id, cd->id, cd->depth);
        }
    }
}

bool DetectUrilenValidateContent(const Signature *s, int list, const char **sigerror)
{
    const SigMatch *sm = s->init_data->smlists[list];
    for ( ; sm != NULL;  sm = sm->next) {
        if (sm->type != DETECT_CONTENT) {
            continue;
        }
        DetectContentData *cd = (DetectContentData *)sm->ctx;
        if (cd == NULL) {
            continue;
        }

        if (cd->depth && cd->depth < cd->content_len) {
            *sigerror = "depth or urilen smaller than content len";
            SCLogError(SC_ERR_INVALID_SIGNATURE, "depth or urilen %u smaller "
                    "than content len %u", cd->depth, cd->content_len);
            return false;
        }
    }
    return true;
}

#ifdef UNITTESTS

#include "stream.h"
#include "stream-tcp-private.h"
#include "stream-tcp-reassemble.h"
#include "detect-engine.h"
#include "detect-engine-mpm.h"
#include "app-layer-parser.h"

/** \test   Test the Urilen keyword setup */
static int DetectUrilenParseTest01(void)
{
    int ret = 0;
    DetectUrilenData *urilend = NULL;

    urilend = DetectUrilenParse("10");
    if (urilend != NULL) {
        if (urilend->urilen1 == 10 && urilend->mode == DETECT_URILEN_EQ &&
            !urilend->raw_buffer)
            ret = 1;

        DetectUrilenFree(NULL, urilend);
    }
    return ret;
}

/** \test   Test the Urilen keyword setup */
static int DetectUrilenParseTest02(void)
{
    int ret = 0;
    DetectUrilenData *urilend = NULL;

    urilend = DetectUrilenParse(" < 10  ");
    if (urilend != NULL) {
        if (urilend->urilen1 == 10 && urilend->mode == DETECT_URILEN_LT &&
            !urilend->raw_buffer)
            ret = 1;

        DetectUrilenFree(NULL, urilend);
    }
    return ret;
}

/** \test   Test the Urilen keyword setup */
static int DetectUrilenParseTest03(void)
{
    int ret = 0;
    DetectUrilenData *urilend = NULL;

    urilend = DetectUrilenParse(" > 10 ");
    if (urilend != NULL) {
        if (urilend->urilen1 == 10 && urilend->mode == DETECT_URILEN_GT &&
            !urilend->raw_buffer)
            ret = 1;

        DetectUrilenFree(NULL, urilend);
    }
    return ret;
}

/** \test   Test the Urilen keyword setup */
static int DetectUrilenParseTest04(void)
{
    int ret = 0;
    DetectUrilenData *urilend = NULL;

    urilend = DetectUrilenParse(" 5 <> 10 ");
    if (urilend != NULL) {
        if (urilend->urilen1 == 5 && urilend->urilen2 == 10 &&
            urilend->mode == DETECT_URILEN_RA &&
            !urilend->raw_buffer)
            ret = 1;

        DetectUrilenFree(NULL, urilend);
    }
    return ret;
}

/** \test   Test the Urilen keyword setup */
static int DetectUrilenParseTest05(void)
{
    int ret = 0;
    DetectUrilenData *urilend = NULL;

    urilend = DetectUrilenParse("5<>10,norm");
    if (urilend != NULL) {
        if (urilend->urilen1 == 5 && urilend->urilen2 == 10 &&
            urilend->mode == DETECT_URILEN_RA &&
            !urilend->raw_buffer)
            ret = 1;

        DetectUrilenFree(NULL, urilend);
    }
    return ret;
}

/** \test   Test the Urilen keyword setup */
static int DetectUrilenParseTest06(void)
{
    int ret = 0;
    DetectUrilenData *urilend = NULL;

    urilend = DetectUrilenParse("5<>10,raw");
    if (urilend != NULL) {
        if (urilend->urilen1 == 5 && urilend->urilen2 == 10 &&
            urilend->mode == DETECT_URILEN_RA &&
            urilend->raw_buffer)
            ret = 1;

        DetectUrilenFree(NULL, urilend);
    }
    return ret;
}

/** \test   Test the Urilen keyword setup */
static int DetectUrilenParseTest07(void)
{
    int ret = 0;
    DetectUrilenData *urilend = NULL;

    urilend = DetectUrilenParse(">10, norm ");
    if (urilend != NULL) {
        if (urilend->urilen1 == 10 && urilend->mode == DETECT_URILEN_GT &&
            !urilend->raw_buffer)
            ret = 1;

        DetectUrilenFree(NULL, urilend);
    }
    return ret;
}

/** \test   Test the Urilen keyword setup */
static int DetectUrilenParseTest08(void)
{
    int ret = 0;
    DetectUrilenData *urilend = NULL;

    urilend = DetectUrilenParse("<10, norm ");
    if (urilend != NULL) {
        if (urilend->urilen1 == 10 && urilend->mode == DETECT_URILEN_LT &&
            !urilend->raw_buffer)
            ret = 1;

        DetectUrilenFree(NULL, urilend);
    }
    return ret;
}

/** \test   Test the Urilen keyword setup */
static int DetectUrilenParseTest09(void)
{
    int ret = 0;
    DetectUrilenData *urilend = NULL;

    urilend = DetectUrilenParse(">10, raw ");
    if (urilend != NULL) {
        if (urilend->urilen1 == 10 && urilend->mode == DETECT_URILEN_GT &&
            urilend->raw_buffer)
            ret = 1;

        DetectUrilenFree(NULL, urilend);
    }
    return ret;
}

/** \test   Test the Urilen keyword setup */
static int DetectUrilenParseTest10(void)
{
    int ret = 0;
    DetectUrilenData *urilend = NULL;

    urilend = DetectUrilenParse("<10, raw ");
    if (urilend != NULL) {
        if (urilend->urilen1 == 10 && urilend->mode == DETECT_URILEN_LT &&
            urilend->raw_buffer)
            ret = 1;

        DetectUrilenFree(NULL, urilend);
    }
    return ret;
}

/**
 * \brief this function is used to initialize the detection engine context and
 *        setup the signature with passed values.
 *
 */

static int DetectUrilenInitTest(DetectEngineCtx **de_ctx, Signature **sig,
                                DetectUrilenData **urilend, const char *str)
{
    char fullstr[1024];
    int result = 0;

    *de_ctx = NULL;
    *sig = NULL;

    if (snprintf(fullstr, 1024, "alert ip any any -> any any (msg:\"Urilen "
                                "test\"; urilen:%s; sid:1;)", str) >= 1024) {
        goto end;
    }

    *de_ctx = DetectEngineCtxInit();
    if (*de_ctx == NULL) {
        goto end;
    }

    (*de_ctx)->flags |= DE_QUIET;

    (*de_ctx)->sig_list = SigInit(*de_ctx, fullstr);
    if ((*de_ctx)->sig_list == NULL) {
        goto end;
    }

    *sig = (*de_ctx)->sig_list;

    *urilend = DetectUrilenParse(str);

    result = 1;

end:
    return result;
}

/**
 * \test DetectUrilenSetpTest01 is a test for setting up an valid urilen values
 *       with valid "<>" operator and include spaces arround the given values.
 *       In the test the values are setup with initializing the detection engine
 *       context and setting up the signature itself.
 */

static int DetectUrilenSetpTest01(void)
{

    DetectUrilenData *urilend = NULL;
    uint8_t res = 0;
    Signature *sig = NULL;
    DetectEngineCtx *de_ctx = NULL;

    res = DetectUrilenInitTest(&de_ctx, &sig, &urilend, "1 <> 2 ");
    if (res == 0) {
        goto end;
    }

    if(urilend == NULL)
        goto cleanup;

    if (urilend != NULL) {
        if (urilend->urilen1 == 1 && urilend->urilen2 == 2 &&
                urilend->mode == DETECT_URILEN_RA)
            res = 1;
    }

cleanup:
    if (urilend) SCFree(urilend);
    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
end:
    return res;
}

/** \test Check a signature with gievn urilen */
static int DetectUrilenSigTest01(void)
{
    int result = 0;
    Flow f;
    uint8_t httpbuf1[] = "POST /suricata HTTP/1.0\r\n"
                         "Host: foo.bar.tld\r\n"
                         "\r\n";
    uint32_t httplen1 = sizeof(httpbuf1) - 1; /* minus the \0 */
    TcpSession ssn;
    Packet *p = NULL;
    Signature *s = NULL;
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&th_v, 0, sizeof(th_v));
    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    p = UTHBuildPacket(NULL, 0, IPPROTO_TCP);

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;
    f.flags |= FLOW_IPV4;

    p->flow = &f;
    p->flowflags |= FLOW_PKT_TOSERVER;
    p->flowflags |= FLOW_PKT_ESTABLISHED;
    p->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    f.alproto = ALPROTO_HTTP1;

    StreamTcpInitConfig(true);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        goto end;
    }

    de_ctx->flags |= DE_QUIET;

    s = de_ctx->sig_list = SigInit(de_ctx,
                                   "alert tcp any any -> any any "
                                   "(msg:\"Testing urilen\"; "
                                   "urilen: <5; sid:1;)");
    if (s == NULL) {
        goto end;
    }

    s = s->next = SigInit(de_ctx,
                          "alert tcp any any -> any any "
                          "(msg:\"Testing http_method\"; "
                           "urilen: >5; sid:2;)");
    if (s == NULL) {
        goto end;
    }

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    int r = AppLayerParserParse(
            NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOSERVER, httpbuf1, httplen1);
    if (r != 0) {
        SCLogDebug("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        goto end;
    }

    HtpState *htp_state = f.alstate;
    if (htp_state == NULL) {
        SCLogDebug("no http state: ");
        goto end;
    }

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);

    if ((PacketAlertCheck(p, 1))) {
        printf("sid 1 alerted, but should not have: \n");
        goto end;
    }
    if (!PacketAlertCheck(p, 2)) {
        printf("sid 2 did not alerted, but should have: \n");
        goto end;
    }

    result = 1;

end:
    if (alp_tctx != NULL)
        AppLayerParserThreadCtxFree(alp_tctx);
    if (de_ctx != NULL) SigGroupCleanup(de_ctx);
    if (de_ctx != NULL) SigCleanSignatures(de_ctx);
    if (de_ctx != NULL) DetectEngineCtxFree(de_ctx);

    StreamTcpFreeConfig(true);
    FLOW_DESTROY(&f);
    UTHFreePackets(&p, 1);
    return result;
}

/**
 * \brief this function registers unit tests for DetectUrilen
 */
void DetectUrilenRegisterTests(void)
{
    UtRegisterTest("DetectUrilenParseTest01", DetectUrilenParseTest01);
    UtRegisterTest("DetectUrilenParseTest02", DetectUrilenParseTest02);
    UtRegisterTest("DetectUrilenParseTest03", DetectUrilenParseTest03);
    UtRegisterTest("DetectUrilenParseTest04", DetectUrilenParseTest04);
    UtRegisterTest("DetectUrilenParseTest05", DetectUrilenParseTest05);
    UtRegisterTest("DetectUrilenParseTest06", DetectUrilenParseTest06);
    UtRegisterTest("DetectUrilenParseTest07", DetectUrilenParseTest07);
    UtRegisterTest("DetectUrilenParseTest08", DetectUrilenParseTest08);
    UtRegisterTest("DetectUrilenParseTest09", DetectUrilenParseTest09);
    UtRegisterTest("DetectUrilenParseTest10", DetectUrilenParseTest10);
    UtRegisterTest("DetectUrilenSetpTest01", DetectUrilenSetpTest01);
    UtRegisterTest("DetectUrilenSigTest01", DetectUrilenSigTest01);
}
#endif /* UNITTESTS */
