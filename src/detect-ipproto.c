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
 * \author Brian Rectanus <brectanu@gmail.com>
 *
 * Implements the ip_proto keyword
 */

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
#include "util-unittest-helper.h"

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

static int DetectIPProtoSetup(DetectEngineCtx *, Signature *, char *);
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
        SCLogError(SC_ERR_PCRE_COMPILE, "pcre compile of \"%s\" failed at offset %" PRId32 ": %s", PARSE_REGEX, eo, eb);
        goto error;
    }

    parse_regex_study = pcre_study(parse_regex, 0, &eb);
    if(eb != NULL)
    {
        SCLogError(SC_ERR_PCRE_STUDY, "pcre study failed: %s", eb);
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
        SCLogError(SC_ERR_PCRE_MATCH, "pcre_exec parse error, ret %" PRId32 ", string %s", ret, optstr);
        goto error;
    }

    for (i = 0; i < (ret - 1); i++) {
        res = pcre_get_substring((char *)optstr, ov, MAX_SUBSTRINGS,
                                 i + 1, &str_ptr);
        if (res < 0) {
            SCLogError(SC_ERR_PCRE_GET_SUBSTRING, "pcre_get_substring failed");
            goto error;
        }
        args[i] = (char *)str_ptr;
    }

    /* Initialize the data */
    data = SCMalloc(sizeof(DetectIPProtoData));
    if (data == NULL)
        goto error;
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
            SCLogError(SC_ERR_INVALID_VALUE, "Malformed protocol name: %s", str_ptr);
            goto error;
        }
        data->proto = (uint8_t)pent->p_proto;
    }
    else {
        if (ByteExtractStringUint8(&data->proto, 10, 0, args[1]) <= 0) {
            SCLogError(SC_ERR_INVALID_VALUE, "Malformed protocol number: %s", str_ptr);
            goto error;
        }
    }

    for (i = 0; i < (ret - 1); i++){
        if (args[i] != NULL)
            SCFree(args[i]);
    }
    return data;

error:
    for (i = 0; i < (ret - 1) && i < 2; i++){
        if (args[i] != NULL)
            SCFree(args[i]);
    }
    if (data != NULL)
        SCFree(data);
    return NULL;
}

/**
 * \internal
 * \brief Setup ip_proto keyword.
 *
 * \param de_ctx Detection engine context
 * \param s Signature
 * \param optstr Options string
 *
 * \return Non-zero on error
 */
static int DetectIPProtoSetup(DetectEngineCtx *de_ctx, Signature *s, char *optstr)
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
    if (data != NULL) SCFree(data);

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

    if (data) SCFree(data);

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

    if (data) SCFree(data);

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
    if (data) SCFree(data);
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
    if (data) SCFree(data);
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
    if (data) SCFree(data);
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
    if (data) SCFree(data);
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
    if (data) SCFree(data);
    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
end:
    return result;
}

static int DetectIPProtoTestSig1(void) {
    int result = 0;
    uint8_t *buf = (uint8_t *)
                    "GET /one/ HTTP/1.1\r\n"
                    "Host: one.example.org\r\n"
                    "\r\n";
    uint16_t buflen = strlen((char *)buf);
    Packet *p = UTHBuildPacket((uint8_t *)buf, buflen, IPPROTO_TCP);
    if (p == NULL)
        goto end;

    char *sigs[4];
    sigs[0] = "alert ip any any -> any any (msg:\"Not tcp\"; ip_proto:!tcp; content:\"GET \"; sid:1;)";
    sigs[1] = "alert ip any any -> any any (msg:\"Less than 7\"; content:\"GET \"; ip_proto:<7; sid:2;)";
    sigs[2] = "alert ip any any -> any any (msg:\"Greater than 5\"; content:\"GET \"; ip_proto:>5; sid:3;)";
    sigs[3] = "alert ip any any -> any any (msg:\"Equals tcp\"; content:\"GET \"; ip_proto:tcp; sid:4;)";

    /* sids to match */
    uint32_t sid[4] = {1, 2, 3, 4};
    /* expected matches for each sid within this packet we are testing */
    uint32_t results[4] = {0, 1, 1, 1};

    /* remember that UTHGenericTest expect the first parameter
     * as an array of packet pointers. And also a bidimensional array of results
     * For example:
     * results[numpacket][position] should hold the number of times
     * that the sid at sid[position] matched that packet (should be always 1..)
     * But here we built it as unidimensional array
     */
    result = UTHGenericTest(&p, 1, sigs, sid, results, 4);

    UTHFreePacket(p);
end:
    DetectSigGroupPrintMemory();
    DetectAddressPrintMemory();
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

