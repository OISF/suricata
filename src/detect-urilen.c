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
#include "detect-engine-state.h"

#include "detect-urilen.h"
#include "util-debug.h"
#include "util-byte.h"
#include "flow-util.h"
#include "stream-tcp.h"

/**
 * \brief Regex for parsing our urilen
 */
#define PARSE_REGEX  "^(?:\\s*)(<|>)?(?:\\s*)([0-9]{1,5})(?:\\s*)(?:(<>)(?:\\s*)([0-9]{1,5}))?\\s*(?:,\\s*(norm|raw))?\\s*$"

static pcre *parse_regex;
static pcre_extra *parse_regex_study;

/*prototypes*/
static int DetectUrilenSetup (DetectEngineCtx *, Signature *, char *);
void DetectUrilenFree (void *);
void DetectUrilenRegisterTests (void);

/**
 * \brief Registration function for urilen: keyword
 */

void DetectUrilenRegister(void)
{
    sigmatch_table[DETECT_AL_URILEN].name = "urilen";
    sigmatch_table[DETECT_AL_URILEN].desc = "match on the length of the HTTP uri";
    sigmatch_table[DETECT_AL_URILEN].url = "https://redmine.openinfosecfoundation.org/projects/suricata/wiki/HTTP-keywords#Urilen";
    sigmatch_table[DETECT_AL_URILEN].Match = NULL;
    sigmatch_table[DETECT_AL_URILEN].alproto = ALPROTO_HTTP;
    sigmatch_table[DETECT_AL_URILEN].AppLayerMatch = NULL /**< We handle this at detect-engine-uri.c now */;
    sigmatch_table[DETECT_AL_URILEN].Setup = DetectUrilenSetup;
    sigmatch_table[DETECT_AL_URILEN].Free = DetectUrilenFree;
    sigmatch_table[DETECT_AL_URILEN].RegisterTests = DetectUrilenRegisterTests;
    sigmatch_table[DETECT_AL_URILEN].flags |= SIGMATCH_PAYLOAD;

    const char *eb;
    int eo;
    int opts = 0;

    parse_regex = pcre_compile(PARSE_REGEX, opts, &eb, &eo, NULL);
    if (parse_regex == NULL) {
        SCLogDebug("pcre compile of \"%s\" failed at offset %" PRId32 ": %s",
                    PARSE_REGEX, eo, eb);
        goto error;
    }

    parse_regex_study = pcre_study(parse_regex, 0, &eb);
    if (eb != NULL) {
        SCLogDebug("pcre study failed: %s", eb);
        goto error;
    }
    return;

error:
    if (parse_regex != NULL)
        pcre_free(parse_regex);
    if (parse_regex_study != NULL)
        pcre_free_study(parse_regex_study);
    return;
}

/**
 * \brief This function is used to parse urilen options passed via urilen: keyword
 *
 * \param urilenstr Pointer to the user provided urilen options
 *
 * \retval urilend pointer to DetectUrilenData on success
 * \retval NULL on failure
 */

DetectUrilenData *DetectUrilenParse (char *urilenstr)
{

    DetectUrilenData *urilend = NULL;
    char *arg1 = NULL;
    char *arg2 = NULL;
    char *arg3 = NULL;
    char *arg4 = NULL;
    char *arg5 = NULL;
#define MAX_SUBSTRINGS 30
    int ret = 0, res = 0;
    int ov[MAX_SUBSTRINGS];

    ret = pcre_exec(parse_regex, parse_regex_study, urilenstr, strlen(urilenstr),
                    0, 0, ov, MAX_SUBSTRINGS);
    if (ret < 3 || ret > 6) {
        SCLogError(SC_ERR_PCRE_PARSE, "urilen option pcre parse error: \"%s\"", urilenstr);
        goto error;
    }
    const char *str_ptr;

    SCLogDebug("ret %d", ret);

    res = pcre_get_substring((char *)urilenstr, ov, MAX_SUBSTRINGS, 1, &str_ptr);
    if (res < 0) {
        SCLogError(SC_ERR_PCRE_GET_SUBSTRING, "pcre_get_substring failed");
        goto error;
    }
    arg1 = (char *) str_ptr;
    SCLogDebug("Arg1 \"%s\"", arg1);

    res = pcre_get_substring((char *)urilenstr, ov, MAX_SUBSTRINGS, 2, &str_ptr);
    if (res < 0) {
        SCLogError(SC_ERR_PCRE_GET_SUBSTRING, "pcre_get_substring failed");
        goto error;
    }
    arg2 = (char *) str_ptr;
    SCLogDebug("Arg2 \"%s\"", arg2);

    if (ret > 3) {
        res = pcre_get_substring((char *)urilenstr, ov, MAX_SUBSTRINGS, 3, &str_ptr);
        if (res < 0) {
            SCLogError(SC_ERR_PCRE_GET_SUBSTRING, "pcre_get_substring failed");
            goto error;
        }
        arg3 = (char *) str_ptr;
        SCLogDebug("Arg3 \"%s\"", arg3);

        if (ret > 4) {
            res = pcre_get_substring((char *)urilenstr, ov, MAX_SUBSTRINGS, 4, &str_ptr);
            if (res < 0) {
                SCLogError(SC_ERR_PCRE_GET_SUBSTRING, "pcre_get_substring failed");
                goto error;
            }
            arg4 = (char *) str_ptr;
            SCLogDebug("Arg4 \"%s\"", arg4);
        }
        if (ret > 5) {
            res = pcre_get_substring((char *)urilenstr, ov, MAX_SUBSTRINGS, 5, &str_ptr);
            if (res < 0) {
                SCLogError(SC_ERR_PCRE_GET_SUBSTRING, "pcre_get_substring failed");
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

    if (arg1[0] == '<')
        urilend->mode = DETECT_URILEN_LT;
    else if (arg1[0] == '>')
        urilend->mode = DETECT_URILEN_GT;
    else
        urilend->mode = DETECT_URILEN_EQ;

    if (arg3 != NULL && strcmp("<>", arg3) == 0) {
        if (strlen(arg1) != 0) {
            SCLogError(SC_ERR_INVALID_ARGUMENT,"Range specified but mode also set");
            goto error;
        }
        urilend->mode = DETECT_URILEN_RA;
    }

    /** set the first urilen value */
    if (ByteExtractStringUint16(&urilend->urilen1,10,strlen(arg2),arg2) <= 0){
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

        if(ByteExtractStringUint16(&urilend->urilen2,10,strlen(arg4),arg4) <= 0)
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

    pcre_free_substring(arg1);
    pcre_free_substring(arg2);
    if (arg3 != NULL)
        pcre_free_substring(arg3);
    if (arg4 != NULL)
        pcre_free_substring(arg4);
    if (arg5 != NULL)
        pcre_free_substring(arg5);
    return urilend;

error:
    if (urilend)
        SCFree(urilend);
    if (arg1 != NULL)
        SCFree(arg1);
    if (arg2 != NULL)
        SCFree(arg2);
    if (arg3 != NULL)
        SCFree(arg3);
    if (arg4 != NULL)
        SCFree(arg4);
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
static int DetectUrilenSetup (DetectEngineCtx *de_ctx, Signature *s, char *urilenstr)
{
    SCEnter();
    DetectUrilenData *urilend = NULL;
    SigMatch *sm = NULL;

    if (s->alproto != ALPROTO_UNKNOWN && s->alproto != ALPROTO_HTTP) {
        SCLogError(SC_ERR_CONFLICTING_RULE_KEYWORDS, "rule contains a non http "
                   "alproto set");
        goto error;
    }

    urilend = DetectUrilenParse(urilenstr);
    if (urilend == NULL)
        goto error;
    sm = SigMatchAlloc();
    if (sm == NULL)
        goto error;
    sm->type = DETECT_AL_URILEN;
    sm->ctx = (void *)urilend;

    if (urilend->raw_buffer)
        SigMatchAppendSMToList(s, sm, DETECT_SM_LIST_HRUDMATCH);
    else
        SigMatchAppendSMToList(s, sm, DETECT_SM_LIST_UMATCH);

    /* Flagged the signature as to inspect the app layer data */
    s->flags |= SIG_FLAG_APPLAYER;
    s->alproto = ALPROTO_HTTP;

    SCReturnInt(0);

error:
    DetectUrilenFree(urilend);
    SCReturnInt(-1);
}

/**
 * \brief this function will free memory associated with DetectUrilenData
 *
 * \param ptr pointer to DetectUrilenData
 */
void DetectUrilenFree(void *ptr)
{
    if (ptr == NULL)
        return;

    DetectUrilenData *urilend = (DetectUrilenData *)ptr;
    SCFree(urilend);
}

#ifdef UNITTESTS

#include "stream.h"
#include "stream-tcp-private.h"
#include "stream-tcp-reassemble.h"
#include "detect-parse.h"
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

        DetectUrilenFree(urilend);
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

        DetectUrilenFree(urilend);
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

        DetectUrilenFree(urilend);
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

        DetectUrilenFree(urilend);
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

        DetectUrilenFree(urilend);
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

        DetectUrilenFree(urilend);
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

        DetectUrilenFree(urilend);
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

        DetectUrilenFree(urilend);
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

        DetectUrilenFree(urilend);
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

        DetectUrilenFree(urilend);
    }
    return ret;
}

/**
 * \brief this function is used to initialize the detection engine context and
 *        setup the signature with passed values.
 *
 */

static int DetectUrilenInitTest(DetectEngineCtx **de_ctx, Signature **sig,
                                DetectUrilenData **urilend, char *str)
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
    f.alproto = ALPROTO_HTTP;

    StreamTcpInitConfig(TRUE);

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

    SCMutexLock(&f.m);
    int r = AppLayerParserParse(alp_tctx, &f, ALPROTO_HTTP, STREAM_TOSERVER, httpbuf1, httplen1);
    if (r != 0) {
        SCLogDebug("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);

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

    StreamTcpFreeConfig(TRUE);
    FLOW_DESTROY(&f);
    UTHFreePackets(&p, 1);
    return result;
}

#endif /* UNITTESTS */

/**
 * \brief this function registers unit tests for DetectUrilen
 */
void DetectUrilenRegisterTests(void)
{
#ifdef UNITTESTS
    UtRegisterTest("DetectUrilenParseTest01", DetectUrilenParseTest01, 1);
    UtRegisterTest("DetectUrilenParseTest02", DetectUrilenParseTest02, 1);
    UtRegisterTest("DetectUrilenParseTest03", DetectUrilenParseTest03, 1);
    UtRegisterTest("DetectUrilenParseTest04", DetectUrilenParseTest04, 1);
    UtRegisterTest("DetectUrilenParseTest05", DetectUrilenParseTest05, 1);
    UtRegisterTest("DetectUrilenParseTest06", DetectUrilenParseTest06, 1);
    UtRegisterTest("DetectUrilenParseTest07", DetectUrilenParseTest07, 1);
    UtRegisterTest("DetectUrilenParseTest08", DetectUrilenParseTest08, 1);
    UtRegisterTest("DetectUrilenParseTest09", DetectUrilenParseTest09, 1);
    UtRegisterTest("DetectUrilenParseTest10", DetectUrilenParseTest10, 1);
    UtRegisterTest("DetectUrilenSetpTest01", DetectUrilenSetpTest01, 1);
    UtRegisterTest("DetectUrilenSigTest01", DetectUrilenSigTest01, 1);
#endif /* UNITTESTS */
}
