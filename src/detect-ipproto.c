/* Copyright (c) 2009 Open Information Security Foundation */

/**
 * \file
 * \author Brian Rectanus <brectanu@gmail.com>
 */

#include <netdb.h>

#include "suricata-common.h"
#include "debug.h"
#include "decode.h"
#include "detect.h"

#include "detect-ipproto.h"

#include "detect-parse.h"
#include "detect-engine.h"
#include "detect-engine-mpm.h"

#include "detect-engine-siggroup.h"
#include "detect-engine-address.h"

#include "util-byte.h"
#include "util-unittest.h"

#include "util-debug.h"

/**
 * \brief Regex for parsing our options
 */
#define PARSE_REGEX  "^\\s*" \
                     "([!<>]?)" \
                     "\\s*([^\\s]+)" \
                     "\\s*$"

static pcre *parse_regex;
static pcre_extra *parse_regex_study;

static int DetectIPProtoSetup(DetectEngineCtx *de_ctx, Signature *s,
                        SigMatch *m, char *optstr);
static DetectIPProtoData *DetectIPProtoParse(const char *optstr);
static void DetectIPProtoRegisterTests(void);

void DetectIPProtoRegister (void) {
    const char *eb;
    int eo;
    int opts = 0;

    sigmatch_table[DETECT_IPPROTO].name = "ip_proto";
    sigmatch_table[DETECT_IPPROTO].Match = NULL;
    sigmatch_table[DETECT_IPPROTO].Setup = DetectIPProtoSetup;
    sigmatch_table[DETECT_IPPROTO].Free  = NULL;
    sigmatch_table[DETECT_IPPROTO].RegisterTests = DetectIPProtoRegisterTests;

    parse_regex = pcre_compile(PARSE_REGEX, opts, &eb, &eo, NULL);
    if(parse_regex == NULL)
    {
        printf("DetectIPProtoRegister: pcre compile of \"%s\" failed at offset %" PRId32 ": %s\n", PARSE_REGEX, eo, eb);
        goto error;
    }

    parse_regex_study = pcre_study(parse_regex, 0, &eb);
    if(eb != NULL)
    {
        printf("DetectIPProtoRegister: pcre study failed: %s\n", eb);
        goto error;
    }
    return;

error:
    /* XXX */
    return;
}

/**
 * \internal
 * \brief Parse ip_proto options string.
 *
 * \param optstr Options string to parse
 *
 * \return New ip_proto data structure
 */
static DetectIPProtoData *DetectIPProtoParse(const char *optstr)
{
    DetectIPProtoData *data = NULL;
    char *args[2] = { NULL, NULL };
#define MAX_SUBSTRINGS 30
    int ret = 0, res = 0;
    int ov[MAX_SUBSTRINGS];
    int i;
    const char *str_ptr;

    /* Execute the regex and populate args with captures. */
    ret = pcre_exec(parse_regex, parse_regex_study, optstr,
                    strlen(optstr), 0, 0, ov, MAX_SUBSTRINGS);
    if (ret != 3) {
        printf("DetectIPProtoParse: parse error, ret %" PRId32
               ", string %s\n", ret, optstr);
        goto error;
    }
    for (i = 0; i < (ret - 1); i++) {
        res = pcre_get_substring((char *)optstr, ov, MAX_SUBSTRINGS,
                                 i + 1, &str_ptr);
        if (res < 0) {
            printf("DetectIPProtoParse: pcre_get_substring failed "
                   "for arg %d\n", i + 1);
            goto error;
        }
        args[i] = (char *)str_ptr;
    }

    /* Initialize the data */
    data = malloc(sizeof(DetectIPProtoData));
    if (data == NULL) {
        printf("DetectIPProtoParse: malloc failed\n");
        goto error;
    }
    data->op = DETECT_IPPROTO_OP_EQ;
    data->proto = 0;

    /* Operator */
    if (*(args[0]) != '\0') {
        data->op = *(args[0]);
    }

    /* Protocol name/number */
    if (!isdigit(*(args[1]))) {
        struct protoent *pent = getprotobyname(args[1]);
        if (pent == NULL) {
            printf("DetectIPProtoParse: Malformed protocol name: %s\n", str_ptr);
            goto error;
        }
        data->proto = (uint8_t)pent->p_proto;
    }
    else {
        if (ByteExtractStringUint8(&data->proto, 10, 0, args[1]) <= 0) {
            printf("DetectIPProtoParse: Malformed protocol number: %s\n", str_ptr);
            goto error;
        }
    }

    for (i = 0; i < (ret - 1); i++){
        if (args[i] != NULL) free(args[i]);
    }
    return data;

error:
    for (i = 0; i < (ret - 1); i++){
        if (args[i] != NULL) free(args[i]);
    }
    if (data != NULL) free(data);
    return NULL;
}

/**
 * \internal
 * \brief Setup ip_proto keyword.
 *
 * \param de_ctx Detection engine context
 * \param s Signature
 * \param m Signature match
 * \param optstr Options string
 *
 * \return Non-zero on error
 */
static int DetectIPProtoSetup(DetectEngineCtx *de_ctx, Signature *s,
                        SigMatch *m, char *optstr)
{
    DetectIPProtoData *data = NULL;
    int ret = 0;
    int i;

    //printf("DetectIPProtoSetup: \'%s\'\n", optstr);

    data = DetectIPProtoParse((const char *)optstr);
    if (data == NULL) {
        ret = -1;
        goto cleanup;
    }

    /* reset our "any" (or "ip") state */
    s->proto.flags &= ~DETECT_PROTO_ANY;
    memset(s->proto.proto, 0x00, sizeof(s->proto.proto));

    switch (data->op) {
        case DETECT_IPPROTO_OP_EQ:
            s->proto.proto[data->proto/8] |= 1 << (data->proto%8);
            break;
        case DETECT_IPPROTO_OP_GT:
            s->proto.proto[data->proto/8] |= 0xff << (data->proto%8);
            for (i = (data->proto/8) + 1; i < (256/8); i++) {
                s->proto.proto[i] = 0xff;
            }
            break;
        case DETECT_IPPROTO_OP_LT:
            for (i = 0; i < (data->proto/8); i++) {
                s->proto.proto[i] = 0xff;
            }
            s->proto.proto[data->proto/8] |= ~(0xff << (data->proto%8));
            break;
        case DETECT_IPPROTO_OP_NOT:
            s->proto.proto[data->proto/8] &= ~(1 << (data->proto%8));
            break;
    }
#if DEBUG
    if (SCLogDebugEnabled()) {
        printf("op='%c' bits=\"", data->op);
        for (i = 0; i < (256/8); i++) {
            printf("%02x", s->proto.proto[i]);
        }
        printf("\"\n");
    }
#endif

    ret = 0;

cleanup:
    if (data != NULL) free(data);

    return ret;
}


/* UNITTESTS */
#ifdef UNITTESTS

#include "detect-engine.h"
#include "detect-parse.h"

static int DetectIPProtoInitTest(DetectEngineCtx **de_ctx, Signature **sig, DetectIPProtoData **data, const char *str) {
    char fullstr[1024];
    int result = 0;

    *de_ctx = NULL;
    *sig = NULL;

    if (snprintf(fullstr, 1024, "alert ip any any -> any any (msg:\"IPProto test\"; ip_proto:%s; sid:1;)", str) >= 1024) {
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
    if ((*sig)->proto.flags & DETECT_PROTO_ANY) {
        goto end;
    }

    *data = DetectIPProtoParse(str);

    result = 1;

end:
    return result;
}

/**
 * \test DetectIPProtoTestParse01 is a test for an invalid proto number
 */
static int DetectIPProtoTestParse01(void) {
    int result = 0;
    DetectIPProtoData *data = NULL;
    data = DetectIPProtoParse("999");
    if (data == NULL) {
        result = 1;
    }

    if (data) free(data);

    return result;
}

/**
 * \test DetectIPProtoTestParse02 is a test for an invalid proto name
 */
static int DetectIPProtoTestParse02(void) {
    int result = 0;
    DetectIPProtoData *data = NULL;
    data = DetectIPProtoParse("foobarbooeek");
    if (data == NULL) {
        result = 1;
    }

    if (data) free(data);

    return result;
}

/**
 * \test DetectIPProtoTestSetup01 is a test for a protocol number
 */
static int DetectIPProtoTestSetup01(void) {
    DetectIPProtoData *data = NULL;
    Signature *sig = NULL;
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;
    int i;

    result = DetectIPProtoInitTest(&de_ctx, &sig, &data, "14");
    if (result == 0) {
        goto end;
    }

    result = 0;

    if (data == NULL) {
        goto cleanup;
    }

    if (   (data->op != DETECT_IPPROTO_OP_EQ)
        || (data->proto != 14))
    {
        goto cleanup;
    }

    /* The 6th bit is the only one that should be set */
    if (sig->proto.proto[1] != 0x40) {
        goto cleanup;
    }
    for (i = 2; i < 256/8; i++) {
        if (sig->proto.proto[i] != 0) {
            goto cleanup;
        }
    }

    result = 1;

cleanup:
    if (data) free(data);
    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
end:
    return result;
}

/**
 * \test DetectIPProtoTestSetup02 is a test for a protocol name
 */
static int DetectIPProtoTestSetup02(void) {
    DetectIPProtoData *data = NULL;
    Signature *sig = NULL;
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    result = DetectIPProtoInitTest(&de_ctx, &sig, &data, "tcp");
    if (result == 0) {
        goto end;
    }

    result = 0;

    if (data == NULL) {
        goto cleanup;
    }

    if (   (data->op != DETECT_IPPROTO_OP_EQ)
        || (data->proto != 6))
    {
        goto cleanup;
    }

    /* The 6th bit is the only one that should be set */
    if (sig->proto.proto[0] != 0x40) {
        goto cleanup;
    }

    result = 1;

cleanup:
    if (data) free(data);
    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
end:
    return result;
}

/**
 * \test DetectIPProtoTestSetup03 is a test for a < operator
 */
static int DetectIPProtoTestSetup03(void) {
    DetectIPProtoData *data = NULL;
    Signature *sig = NULL;
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    result = DetectIPProtoInitTest(&de_ctx, &sig, &data, "<14");
    if (result == 0) {
        goto end;
    }

    result = 0;

    if (data == NULL) {
        goto cleanup;
    }

    if (   (data->op != DETECT_IPPROTO_OP_LT)
        || (data->proto != 14))
    {
        goto cleanup;
    }

    if (   (sig->proto.proto[0] != 0xff)
        || (sig->proto.proto[1] != 0x3f))
    {
        goto cleanup;
    }

    result = 1;

cleanup:
    if (data) free(data);
    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
end:
    return result;
}

/**
 * \test DetectIPProtoTestSetup04 is a test for a > operator
 */
static int DetectIPProtoTestSetup04(void) {
    DetectIPProtoData *data = NULL;
    Signature *sig = NULL;
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;
    int i;

    result = DetectIPProtoInitTest(&de_ctx, &sig, &data, ">14");
    if (result == 0) {
        goto end;
    }

    result = 0;

    if (data == NULL) {
        goto cleanup;
    }

    if (   (data->op != DETECT_IPPROTO_OP_GT)
        || (data->proto != 14))
    {
        goto cleanup;
    }

    if (sig->proto.proto[1] != 0xc0) {
        goto cleanup;
    }
    for (i = 2; i < 256/8; i++) {
        if (sig->proto.proto[i] != 0xff) {
            goto cleanup;
        }
    }

    result = 1;

cleanup:
    if (data) free(data);
    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
end:
    return result;
}

/**
 * \test DetectIPProtoTestSetup05 is a test for a ! operator
 */
static int DetectIPProtoTestSetup05(void) {
    DetectIPProtoData *data = NULL;
    Signature *sig = NULL;
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;
    int i;

    result = DetectIPProtoInitTest(&de_ctx, &sig, &data, "!14");
    if (result == 0) {
        goto end;
    }

    result = 0;

    if (data == NULL) {
        goto cleanup;
    }

    if (   (data->op != DETECT_IPPROTO_OP_NOT)
        || (data->proto != 14))
    {
        goto cleanup;
    }

    for (i = 1; i < 256/8; i++) {
        if (sig->proto.proto[i] != 0) {
            goto cleanup;
        }
    }

    result = 1;

cleanup:
    if (data) free(data);
    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
end:
    return result;
}

static int DetectIPProtoTestSig1(void) {
    uint8_t *buf = (uint8_t *)
                    "GET /one/ HTTP/1.1\r\n"
                    "Host: one.example.org\r\n"
                    "\r\n";
    uint16_t buflen = strlen((char *)buf);
    Packet p;
    Signature *s = NULL;
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx;
    int result = 0;

    memset(&th_v, 0, sizeof(th_v));
    memset(&p, 0, sizeof(p));
    p.src.family = AF_INET;
    p.dst.family = AF_INET;
    p.payload = buf;
    p.payload_len = buflen;
    p.proto = IPPROTO_TCP;

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        goto end;
    }

    //de_ctx->flags |= DE_QUIET;

    s = de_ctx->sig_list = SigInit(de_ctx,"alert ip any any -> any any (msg:\"Not tcp\"; ip_proto:!tcp; content:\"GET \"; sid:1;)");
    if (s == NULL) {
        goto end;
    }

    s = s->next = SigInit(de_ctx,"alert ip any any -> any any (msg:\"Less than 7\"; content:\"GET \"; ip_proto:<7; sid:2;)");
    if (s == NULL) {
        goto end;
    }

    s = s->next = SigInit(de_ctx,"alert ip any any -> any any (msg:\"Greater than 5\"; content:\"GET \"; ip_proto:>5; sid:3;)");
    if (s == NULL) {
        goto end;
    }

    s = s->next = SigInit(de_ctx,"alert ip any any -> any any (msg:\"Equals tcp\"; content:\"GET \"; ip_proto:tcp; sid:4;)");
    if (s == NULL) {
        goto end;
    }

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    SigMatchSignatures(&th_v, de_ctx, det_ctx, &p);
    if (PacketAlertCheck(&p, 1)) {
        printf("sid 1 alerted, but should not have: ");
        goto cleanup;
    } else if (PacketAlertCheck(&p, 2) == 0) {
        printf("sid 2 did not alert, but should have: ");
        goto cleanup;
    } else if (PacketAlertCheck(&p, 3) == 0) {
        printf("sid 3 did not alert, but should have: ");
        goto cleanup;
    } else if (PacketAlertCheck(&p, 4) == 0) {
        printf("sid 4 did not alert, but should have: ");
        goto cleanup;
    }

    result = 1;

cleanup:
    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);

    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);

    DetectSigGroupPrintMemory();
    DetectAddressPrintMemory();

end:
    return result;
}

#endif /* UNITTESTS */

/**
 * \internal
 * \brief Register ip_proto tests.
 */
static void DetectIPProtoRegisterTests(void) {
#ifdef UNITTESTS
    UtRegisterTest("DetectIPProtoTestParse01", DetectIPProtoTestParse01, 1);
    UtRegisterTest("DetectIPProtoTestParse02", DetectIPProtoTestParse02, 1);
    UtRegisterTest("DetectIPProtoTestSetup01", DetectIPProtoTestSetup01, 1);
    UtRegisterTest("DetectIPProtoTestSetup02", DetectIPProtoTestSetup02, 1);
    UtRegisterTest("DetectIPProtoTestSetup03", DetectIPProtoTestSetup03, 1);
    UtRegisterTest("DetectIPProtoTestSetup04", DetectIPProtoTestSetup04, 1);
    UtRegisterTest("DetectIPProtoTestSetup05", DetectIPProtoTestSetup05, 1);
    UtRegisterTest("DetectIPProtoTestSig1", DetectIPProtoTestSig1, 1);
#endif /* UNITTESTS */
}

