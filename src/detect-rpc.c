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
 * \author Pablo Rincon <pablo.rincon.crespo@gmail.com>
 *
 * Implements RPC keyword
 */

#include "suricata-common.h"
#ifdef UNITTESTS
#include "util-unittest-helper.h"
#include "util-unittest.h"
#include "detect-engine-build.h"
#include "detect-engine.h"
#endif

#include "detect-rpc.h"
#include "detect-parse.h"

#include "util-byte.h"

/**
 * \brief Regex for parsing our rpc options
 */
#define PARSE_REGEX  "^\\s*([0-9]{0,10})\\s*(?:,\\s*([0-9]{0,10}|[*])\\s*(?:,\\s*([0-9]{0,10}|[*]))?)?\\s*$"

static DetectParseRegex parse_regex;

static int DetectRpcMatch (DetectEngineThreadCtx *, Packet *,
        const Signature *, const SigMatchCtx *);
static int DetectRpcSetup (DetectEngineCtx *, Signature *, const char *);
#ifdef UNITTESTS
static void DetectRpcRegisterTests(void);
#endif
void DetectRpcFree(DetectEngineCtx *, void *);

/**
 * \brief Registration function for rpc keyword
 */
void DetectRpcRegister (void)
{
    sigmatch_table[DETECT_RPC].name = "rpc";
    sigmatch_table[DETECT_RPC].desc = "match RPC procedure numbers and RPC version";
    sigmatch_table[DETECT_RPC].url = "/rules/payload-keywords.html#rpc";
    sigmatch_table[DETECT_RPC].Match = DetectRpcMatch;
    sigmatch_table[DETECT_RPC].Setup = DetectRpcSetup;
    sigmatch_table[DETECT_RPC].Free  = DetectRpcFree;
#ifdef UNITTESTS
    sigmatch_table[DETECT_RPC].RegisterTests = DetectRpcRegisterTests;
#endif
    DetectSetupParseRegexes(PARSE_REGEX, &parse_regex);
}

/*
 * returns 0: no match
 *         1: match
 *        -1: error
 */

/**
 * \brief This function is used to match rpc request set on a packet with those passed via rpc
 *
 * \param t pointer to thread vars
 * \param det_ctx pointer to the pattern matcher thread
 * \param p pointer to the current packet
 * \param m pointer to the sigmatch that we will cast into DetectRpcData
 *
 * \retval 0 no match
 * \retval 1 match
 */
static int DetectRpcMatch (DetectEngineThreadCtx *det_ctx, Packet *p,
        const Signature *s, const SigMatchCtx *ctx)
{
    /* PrintRawDataFp(stdout, p->payload, p->payload_len); */
    const DetectRpcData *rd = (const DetectRpcData *)ctx;
    char *rpcmsg = (char *)p->payload;

    if (PKT_IS_TCP(p)) {
        /* if Rpc msg too small */
        if (p->payload_len < 28) {
            SCLogDebug("TCP packet to small for the rpc msg (%u)", p->payload_len);
            return 0;
        }
        rpcmsg += 4;
    } else if (PKT_IS_UDP(p)) {
        /* if Rpc msg too small */
        if (p->payload_len < 24) {
            SCLogDebug("UDP packet to small for the rpc msg (%u)", p->payload_len);
            return 0;
        }
    } else {
        SCLogDebug("No valid proto for the rpc message");
        return 0;
    }

    /* Point through the rpc msg structure. Use SCNtohl() to compare values */
    RpcMsg *msg = (RpcMsg *)rpcmsg;

    /* If its not a call, no match */
    if (SCNtohl(msg->type) != 0) {
        SCLogDebug("RPC message type is not a call");
        return 0;
    }

    if (SCNtohl(msg->prog) != rd->program)
        return 0;

    if ((rd->flags & DETECT_RPC_CHECK_VERSION) && SCNtohl(msg->vers) != rd->program_version)
        return 0;

    if ((rd->flags & DETECT_RPC_CHECK_PROCEDURE) && SCNtohl(msg->proc) != rd->procedure)
        return 0;

    SCLogDebug("prog:%u pver:%u proc:%u matched", SCNtohl(msg->prog), SCNtohl(msg->vers), SCNtohl(msg->proc));
    return 1;
}

/**
 * \brief This function is used to parse rpc options passed via rpc keyword
 *
 * \param de_ctx Pointer to the detection engine context
 * \param rpcstr Pointer to the user provided rpc options
 *
 * \retval rd pointer to DetectRpcData on success
 * \retval NULL on failure
 */
static DetectRpcData *DetectRpcParse (DetectEngineCtx *de_ctx, const char *rpcstr)
{
    DetectRpcData *rd = NULL;
    char *args[3] = {NULL,NULL,NULL};
    int ret = 0, res = 0;
    size_t pcre2_len;

    ret = DetectParsePcreExec(&parse_regex, rpcstr, 0, 0);
    if (ret < 1 || ret > 4) {
        SCLogError(SC_ERR_PCRE_MATCH, "parse error, ret %" PRId32 ", string %s", ret, rpcstr);
        goto error;
    }

    if (ret > 1) {
        const char *str_ptr;
        res = pcre2_substring_get_bynumber(
                parse_regex.match, 1, (PCRE2_UCHAR8 **)&str_ptr, &pcre2_len);
        if (res < 0) {
            SCLogError(SC_ERR_PCRE_GET_SUBSTRING, "pcre2_substring_get_bynumber failed");
            goto error;
        }
        args[0] = (char *)str_ptr;

        if (ret > 2) {
            res = pcre2_substring_get_bynumber(
                    parse_regex.match, 2, (PCRE2_UCHAR8 **)&str_ptr, &pcre2_len);
            if (res < 0) {
                SCLogError(SC_ERR_PCRE_GET_SUBSTRING, "pcre2_substring_get_bynumber failed");
                goto error;
            }
            args[1] = (char *)str_ptr;
        }
        if (ret > 3) {
            res = pcre2_substring_get_bynumber(
                    parse_regex.match, 3, (PCRE2_UCHAR8 **)&str_ptr, &pcre2_len);
            if (res < 0) {
                SCLogError(SC_ERR_PCRE_GET_SUBSTRING, "pcre2_substring_get_bynumber failed");
                goto error;
            }
            args[2] = (char *)str_ptr;
        }
    }

    rd = SCMalloc(sizeof(DetectRpcData));
    if (unlikely(rd == NULL))
        goto error;
    rd->flags = 0;
    rd->program = 0;
    rd->program_version = 0;
    rd->procedure = 0;

    int i;
    for (i = 0; i < (ret - 1); i++) {
        if (args[i]) {
            switch (i) {
                case 0:
                    if (StringParseUint32(&rd->program, 10, strlen(args[i]), args[i]) <= 0) {
                        SCLogError(SC_ERR_INVALID_ARGUMENT, "Invalid size specified for the rpc program:\"%s\"", args[i]);
                        goto error;
                    }
                    rd->flags |= DETECT_RPC_CHECK_PROGRAM;
                    break;
                case 1:
                    if (args[i][0] != '*') {
                        if (StringParseUint32(&rd->program_version, 10, strlen(args[i]), args[i]) <= 0) {
                            SCLogError(SC_ERR_INVALID_ARGUMENT, "Invalid size specified for the rpc version:\"%s\"", args[i]);
                            goto error;
                        }
                        rd->flags |= DETECT_RPC_CHECK_VERSION;
                    }
                    break;
                case 2:
                    if (args[i][0] != '*') {
                        if (StringParseUint32(&rd->procedure, 10, strlen(args[i]), args[i]) <= 0) {
                            SCLogError(SC_ERR_INVALID_ARGUMENT, "Invalid size specified for the rpc procedure:\"%s\"", args[i]);
                            goto error;
                        }
                        rd->flags |= DETECT_RPC_CHECK_PROCEDURE;
                    }
                break;
            }
        } else {
            SCLogError(SC_ERR_INVALID_VALUE, "invalid rpc option %s",rpcstr);
            goto error;
        }
    }
    for (i = 0; i < (ret -1); i++){
        if (args[i] != NULL)
            pcre2_substring_free((PCRE2_UCHAR8 *)args[i]);
    }
    return rd;

error:
    for (i = 0; i < (ret -1) && i < 3; i++){
        if (args[i] != NULL)
            pcre2_substring_free((PCRE2_UCHAR8 *)args[i]);
    }
    if (rd != NULL)
        DetectRpcFree(de_ctx, rd);
    return NULL;

}

/**
 * \brief this function is used to add the parsed rpcdata into the current signature
 *
 * \param de_ctx pointer to the Detection Engine Context
 * \param s pointer to the Current Signature
 * \param m pointer to the Current SigMatch
 * \param rpcstr pointer to the user provided rpc options
 *
 * \retval 0 on Success
 * \retval -1 on Failure
 */
int DetectRpcSetup (DetectEngineCtx *de_ctx, Signature *s, const char *rpcstr)
{
    DetectRpcData *rd = NULL;
    SigMatch *sm = NULL;

    rd = DetectRpcParse(de_ctx, rpcstr);
    if (rd == NULL) goto error;

    sm = SigMatchAlloc();
    if (sm == NULL)
        goto error;

    sm->type = DETECT_RPC;
    sm->ctx = (SigMatchCtx *)rd;

    SigMatchAppendSMToList(s, sm, DETECT_SM_LIST_MATCH);
    s->flags |= SIG_FLAG_REQUIRE_PACKET;

    return 0;

error:
    if (rd != NULL) DetectRpcFree(de_ctx, rd);
    if (sm != NULL) SCFree(sm);
    return -1;

}

/**
 * \brief this function will free memory associated with DetectRpcData
 *
 * \param rd pointer to DetectRpcData
 */
void DetectRpcFree(DetectEngineCtx *de_ctx, void *ptr)
{
    SCEnter();

    if (ptr == NULL) {
        SCReturn;
    }

    DetectRpcData *rd = (DetectRpcData *)ptr;
    SCFree(rd);

    SCReturn;
}

#ifdef UNITTESTS
/**
 * \test DetectRpcTestParse01 is a test to make sure that we return "something"
 *  when given valid rpc opt
 */
static int DetectRpcTestParse01 (void)
{
    DetectRpcData *rd = DetectRpcParse(NULL, "123,444,555");
    FAIL_IF_NULL(rd);

    DetectRpcFree(NULL, rd);
    PASS;
}

/**
 * \test DetectRpcTestParse02 is a test for setting the established rpc opt
 */
static int DetectRpcTestParse02 (void)
{
    DetectRpcData *rd = NULL;
    rd = DetectRpcParse(NULL, "111,222,333");
    FAIL_IF_NULL(rd);
    FAIL_IF_NOT(rd->flags & DETECT_RPC_CHECK_PROGRAM);
    FAIL_IF_NOT(rd->flags & DETECT_RPC_CHECK_VERSION);
    FAIL_IF_NOT(rd->flags & DETECT_RPC_CHECK_PROCEDURE);
    FAIL_IF_NOT(rd->program == 111);
    FAIL_IF_NOT(rd->program_version == 222);
    FAIL_IF_NOT(rd->procedure == 333);

    DetectRpcFree(NULL, rd);

    PASS;
}

/**
 * \test DetectRpcTestParse03 is a test for checking the wildcards
 * and not specified fields
 */
static int DetectRpcTestParse03 (void)
{
    DetectRpcData *rd = NULL;

    rd = DetectRpcParse(NULL, "111,*,333");
    FAIL_IF_NULL(rd);

    FAIL_IF_NOT(rd->flags & DETECT_RPC_CHECK_PROGRAM);
    FAIL_IF(rd->flags & DETECT_RPC_CHECK_VERSION);
    FAIL_IF_NOT(rd->flags & DETECT_RPC_CHECK_PROCEDURE);
    FAIL_IF_NOT(rd->program == 111);
    FAIL_IF_NOT(rd->program_version == 0);
    FAIL_IF_NOT(rd->procedure == 333);

    DetectRpcFree(NULL, rd);

    rd = DetectRpcParse(NULL, "111,222,*");
    FAIL_IF_NULL(rd);

    FAIL_IF_NOT(rd->flags & DETECT_RPC_CHECK_PROGRAM);
    FAIL_IF_NOT(rd->flags & DETECT_RPC_CHECK_VERSION);
    FAIL_IF(rd->flags & DETECT_RPC_CHECK_PROCEDURE);
    FAIL_IF_NOT(rd->program == 111);
    FAIL_IF_NOT(rd->program_version == 222);
    FAIL_IF_NOT(rd->procedure == 0);

    DetectRpcFree(NULL, rd);

    rd = DetectRpcParse(NULL, "111,*,*");
    FAIL_IF_NULL(rd);

    FAIL_IF_NOT(rd->flags & DETECT_RPC_CHECK_PROGRAM);
    FAIL_IF(rd->flags & DETECT_RPC_CHECK_VERSION);
    FAIL_IF(rd->flags & DETECT_RPC_CHECK_PROCEDURE);
    FAIL_IF_NOT(rd->program == 111);
    FAIL_IF_NOT(rd->program_version == 0);
    FAIL_IF_NOT(rd->procedure == 0);

    DetectRpcFree(NULL, rd);

    rd = DetectRpcParse(NULL, "111,222");
    FAIL_IF_NULL(rd);

    FAIL_IF_NOT(rd->flags & DETECT_RPC_CHECK_PROGRAM);
    FAIL_IF_NOT(rd->flags & DETECT_RPC_CHECK_VERSION);
    FAIL_IF(rd->flags & DETECT_RPC_CHECK_PROCEDURE);
    FAIL_IF_NOT(rd->program == 111);
    FAIL_IF_NOT(rd->program_version == 222);
    FAIL_IF_NOT(rd->procedure == 0);

    DetectRpcFree(NULL, rd);

    rd = DetectRpcParse(NULL, "111");
    FAIL_IF_NULL(rd);

    FAIL_IF_NOT(rd->flags & DETECT_RPC_CHECK_PROGRAM);
    FAIL_IF(rd->flags & DETECT_RPC_CHECK_VERSION);
    FAIL_IF(rd->flags & DETECT_RPC_CHECK_PROCEDURE);
    FAIL_IF_NOT(rd->program == 111);
    FAIL_IF_NOT(rd->program_version == 0);
    FAIL_IF_NOT(rd->procedure == 0);

    DetectRpcFree(NULL, rd);
    PASS;
}

/**
 * \test DetectRpcTestParse04 is a test for check the discarding of empty options
 */
static int DetectRpcTestParse04 (void)
{
    DetectRpcData *rd = NULL;
    rd = DetectRpcParse(NULL, "");

    FAIL_IF_NOT_NULL(rd);
    DetectRpcFree(NULL, rd);

    PASS;
}

/**
 * \test DetectRpcTestParse05 is a test for check invalid values
 */
static int DetectRpcTestParse05 (void)
{
    DetectRpcData *rd = NULL;
    rd = DetectRpcParse(NULL, "111,aaa,*");

    FAIL_IF_NOT_NULL(rd);
    DetectRpcFree(NULL, rd);

    PASS;
}

/**
 * \test DetectRpcTestParse05 is a test to check the match function
 */
static int DetectRpcTestSig01(void)
{
    /* RPC Call */
    uint8_t buf[] = {
        /* XID */
        0x64,0xb2,0xb3,0x75,
        /* Message type: Call (0) */
        0x00,0x00,0x00,0x00,
        /* RPC Version (2) */
        0x00,0x00,0x00,0x02,
        /* Program portmap (100000) */
        0x00,0x01,0x86,0xa0,
        /* Program version (2) */
        0x00,0x00,0x00,0x02,
        /* Program procedure (3) = GETPORT */
        0x00,0x00,0x00,0x03,
        /* AUTH_NULL */
        0x00,0x00,0x00,0x00,
        /* Length 0 */
        0x00,0x00,0x00,0x00,
        /* VERIFIER NULL */
        0x00,0x00,0x00,0x00,
        /* Length 0 */
        0x00,0x00,0x00,0x00,
        /* Program portmap */
        0x00,0x01,0x86,0xa2,
        /* Version 2 */
        0x00,0x00,0x00,0x02,
        /* Proto UDP */
        0x00,0x00,0x00,0x11,
        /* Port 0 */
        0x00,0x00,0x00,0x00 };
    uint16_t buflen = sizeof(buf);
    Packet *p = NULL;
    Signature *s = NULL;
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx;

    memset(&th_v, 0, sizeof(th_v));

    p = UTHBuildPacket(buf, buflen, IPPROTO_UDP);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);

    de_ctx->flags |= DE_QUIET;

    s = DetectEngineAppendSig(de_ctx,
            "alert udp any any -> any any (msg:\"RPC Get Port Call\"; rpc:100000, 2, 3; sid:1;)");
    FAIL_IF_NULL(s);

    s = DetectEngineAppendSig(de_ctx,
            "alert udp any any -> any any (msg:\"RPC Get Port Call\"; rpc:100000, 2, *; sid:2;)");
    FAIL_IF_NULL(s);

    s = DetectEngineAppendSig(de_ctx,
            "alert udp any any -> any any (msg:\"RPC Get Port Call\"; rpc:100000, *, 3; sid:3;)");
    FAIL_IF_NULL(s);

    s = DetectEngineAppendSig(de_ctx,
            "alert udp any any -> any any (msg:\"RPC Get Port Call\"; rpc:100000, *, *; sid:4;)");
    FAIL_IF_NULL(s);

    s = DetectEngineAppendSig(de_ctx, "alert udp any any -> any any (msg:\"RPC Get XXX Call.. no "
                                      "match\"; rpc:123456, *, 3; sid:5;)");
    FAIL_IF_NULL(s);

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    FAIL_IF(PacketAlertCheck(p, 1) == 0);
    FAIL_IF(PacketAlertCheck(p, 2) == 0);
    FAIL_IF(PacketAlertCheck(p, 3) == 0);
    FAIL_IF(PacketAlertCheck(p, 4) == 0);
    FAIL_IF(PacketAlertCheck(p, 5) > 0);

    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);

    UTHFreePackets(&p, 1);

    PASS;
}

/**
 * \brief this function registers unit tests for DetectRpc
 */
static void DetectRpcRegisterTests(void)
{
    UtRegisterTest("DetectRpcTestParse01", DetectRpcTestParse01);
    UtRegisterTest("DetectRpcTestParse02", DetectRpcTestParse02);
    UtRegisterTest("DetectRpcTestParse03", DetectRpcTestParse03);
    UtRegisterTest("DetectRpcTestParse04", DetectRpcTestParse04);
    UtRegisterTest("DetectRpcTestParse05", DetectRpcTestParse05);
    UtRegisterTest("DetectRpcTestSig01", DetectRpcTestSig01);
}
#endif /* UNITTESTS */
