/* Copyright (C) 2007-2022 Open Information Security Foundation
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
 * Proto part of the detection engine.
 *
 * \todo move this out of the detection plugin structure
 */

#include "suricata-common.h"

#ifdef UNITTESTS
#include "util-unittest.h"
#endif
/**
 * \brief Parses a protocol sent as a string.
 *
 * \param dp  Pointer to the DetectProto instance which will be updated with the
 *            incoming protocol information.
 * \param str Pointer to the string containing the protocol name.
 *
 * \retval >=0 If proto is detected, -1 otherwise.
 */
int DetectProtoParse(DetectProto *dp, const char *str)
{
    if (strcasecmp(str, "tcp") == 0) {
        dp->proto[IPPROTO_TCP / 8] |= 1 << (IPPROTO_TCP % 8);
        SCLogDebug("TCP protocol detected");
    } else if (strcasecmp(str, "tcp-pkt") == 0) {
        dp->proto[IPPROTO_TCP / 8] |= 1 << (IPPROTO_TCP % 8);
        SCLogDebug("TCP protocol detected, packets only");
        dp->flags |= DETECT_PROTO_ONLY_PKT;
    } else if (strcasecmp(str, "tcp-stream") == 0) {
        dp->proto[IPPROTO_TCP / 8] |= 1 << (IPPROTO_TCP % 8);
        SCLogDebug("TCP protocol detected, stream only");
        dp->flags |= DETECT_PROTO_ONLY_STREAM;
    } else if (strcasecmp(str, "udp") == 0) {
        dp->proto[IPPROTO_UDP / 8] |= 1 << (IPPROTO_UDP % 8);
        SCLogDebug("UDP protocol detected");
    } else if (strcasecmp(str, "icmpv4") == 0) {
        dp->proto[IPPROTO_ICMP / 8] |= 1 << (IPPROTO_ICMP % 8);
        SCLogDebug("ICMPv4 protocol detected");
    } else if (strcasecmp(str, "icmpv6") == 0) {
        dp->proto[IPPROTO_ICMPV6 / 8] |= 1 << (IPPROTO_ICMPV6 % 8);
        SCLogDebug("ICMPv6 protocol detected");
    } else if (strcasecmp(str, "icmp") == 0) {
        dp->proto[IPPROTO_ICMP / 8] |= 1 << (IPPROTO_ICMP % 8);
        dp->proto[IPPROTO_ICMPV6 / 8] |= 1 << (IPPROTO_ICMPV6 % 8);
        SCLogDebug("ICMP protocol detected, sig applies both to ICMPv4 and ICMPv6");
    } else if (strcasecmp(str, "sctp") == 0) {
        dp->proto[IPPROTO_SCTP / 8] |= 1 << (IPPROTO_SCTP % 8);
        SCLogDebug("SCTP protocol detected");
    } else if (strcasecmp(str,"ipv4") == 0 ||
               strcasecmp(str,"ip4") == 0 ) {
        dp->flags |= (DETECT_PROTO_IPV4 | DETECT_PROTO_ANY);
        memset(dp->proto, 0xff, sizeof(dp->proto));
        SCLogDebug("IPv4 protocol detected");
    } else if (strcasecmp(str,"ipv6") == 0 ||
               strcasecmp(str,"ip6") == 0 ) {
        dp->flags |= (DETECT_PROTO_IPV6 | DETECT_PROTO_ANY);
        memset(dp->proto, 0xff, sizeof(dp->proto));
        SCLogDebug("IPv6 protocol detected");
    } else if (strcasecmp(str,"ip") == 0 ||
               strcasecmp(str,"pkthdr") == 0) {
        /* Proto "ip" is treated as an "any" */
        dp->flags |= DETECT_PROTO_ANY;
        memset(dp->proto, 0xff, sizeof(dp->proto));
        SCLogDebug("IP protocol detected");
    } else {
        goto error;

        /** \todo are numeric protocols even valid? */
#if 0
        uint8_t proto_u8; /* Used to avoid sign extension */

        /* Extract out a 0-256 value with validation checks */
        if (ByteExtractStringUint8(&proto_u8, 10, 0, str) == -1) {
            // XXX
            SCLogDebug("DetectProtoParse: Error in extracting byte string");
            goto error;
        }
        proto = (int)proto_u8;

        /* Proto 0 is the same as "ip" above */
        if (proto == IPPROTO_IP) {
            dp->flags |= DETECT_PROTO_ANY;
        } else {
            dp->proto[proto / 8] |= 1<<(proto % 8);
        }
#endif
    }

    return 0;
error:
    return -1;
}

/** \brief see if a DetectProto contains a certain proto
 *  \param dp detect proto to inspect
 *  \param proto protocol (such as IPPROTO_TCP) to look for
 *  \retval 0 protocol not in the set
 *  \retval 1 protocol is in the set */
int DetectProtoContainsProto(const DetectProto *dp, int proto)
{
    if (dp->flags & DETECT_PROTO_ANY)
        return 1;

    if (dp->proto[proto / 8] & (1<<(proto % 8)))
        return 1;

    return 0;
}

/* TESTS */

#ifdef UNITTESTS
#include "detect-engine.h"
#include "detect-parse.h"
/**
 * \brief this function is used to initialize the detection engine context and
 *        setup the signature with passed values.
 */
static int DetectProtoInitTest(DetectEngineCtx **de_ctx, Signature **sig,
                               DetectProto *dp, const char *str)
{
    char fullstr[1024];
    int result = 0;

    *de_ctx = NULL;
    *sig = NULL;

    if (snprintf(fullstr, 1024, "alert %s any any -> any any (msg:\"DetectProto"
            " test\"; sid:1;)", str) >= 1024)
    {
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

    if (DetectProtoParse(dp, str) < 0)
        goto end;

    result = 1;

end:
    return result;
}

/**
 * \test ProtoTestParse01 is a test to make sure that we parse the
 *  protocol correctly, when given valid proto option.
 */
static int ProtoTestParse01 (void)
{
    DetectProto dp;
    memset(&dp,0,sizeof(DetectProto));

    int r = DetectProtoParse(&dp, "6");

    FAIL_IF_NOT(r < 0);

    PASS;
}
/**
 * \test ProtoTestParse02 is a test to make sure that we parse the
 *  protocol correctly, when given "tcp" as proto option.
 */
static int ProtoTestParse02 (void)
{
    DetectProto dp;
    memset(&dp,0,sizeof(DetectProto));

    int r = DetectProtoParse(&dp, "tcp");

    FAIL_IF_NOT(r >= 0);
    FAIL_IF_NOT(dp.proto[(IPPROTO_TCP / 8)] & (1 << (IPPROTO_TCP % 8)));

    PASS;
}
/**
 * \test ProtoTestParse03 is a test to make sure that we parse the
 *  protocol correctly, when given "ip" as proto option.
 */
static int ProtoTestParse03 (void)
{
    DetectProto dp;
    memset(&dp,0,sizeof(DetectProto));

    int r = DetectProtoParse(&dp, "ip");

    FAIL_IF_NOT(r >= 0);
    FAIL_IF_NOT(dp.flags & DETECT_PROTO_ANY);

    PASS;
}

/**
 * \test ProtoTestParse04 is a test to make sure that we do not parse the
 *  protocol, when given an invalid proto option.
 */
static int ProtoTestParse04 (void)
{
    DetectProto dp;
    memset(&dp,0,sizeof(DetectProto));

    /* Check for a bad number */
    int r = DetectProtoParse(&dp, "4242");

    FAIL_IF_NOT(r < 0);

    PASS;
}

/**
 * \test ProtoTestParse05 is a test to make sure that we do not parse the
 *  protocol, when given an invalid proto option.
 */
static int ProtoTestParse05 (void)
{
    DetectProto dp;
    memset(&dp,0,sizeof(DetectProto));

    /* Check for a bad string */
    int r = DetectProtoParse(&dp, "tcp/udp");

    FAIL_IF_NOT(r < 0);

    PASS;
}

/**
 * \test make sure that we properly parse tcp-pkt
 */
static int ProtoTestParse06 (void)
{
    DetectProto dp;
    memset(&dp,0,sizeof(DetectProto));

    /* Check for a bad string */
    int r = DetectProtoParse(&dp, "tcp-pkt");

    FAIL_IF(r < 0);
    FAIL_IF_NOT(dp.flags & DETECT_PROTO_ONLY_PKT);

    PASS;
}

/**
 * \test make sure that we properly parse tcp-stream
 */
static int ProtoTestParse07 (void)
{
    DetectProto dp;
    memset(&dp,0,sizeof(DetectProto));

    /* Check for a bad string */
    int r = DetectProtoParse(&dp, "tcp-stream");

    FAIL_IF(r < 0);
    FAIL_IF_NOT(dp.flags & DETECT_PROTO_ONLY_STREAM);

    PASS;
}

/**
 * \test DetectIPProtoTestSetup01 is a test for a protocol setting up in
 *       signature.
 */
static int DetectProtoTestSetup01(void)
{
    DetectProto dp;
    Signature *sig = NULL;
    DetectEngineCtx *de_ctx = NULL;
    int i;

    memset(&dp, 0, sizeof(dp));

    FAIL_IF_NOT(DetectProtoInitTest(&de_ctx, &sig, &dp, "tcp"));

    /* The signature proto should be TCP */
    FAIL_IF_NOT(sig->proto.proto[(IPPROTO_TCP / 8)] & (1 << (IPPROTO_TCP % 8)));

    for (i = 2; i < 256 / 8; i++) {
        FAIL_IF(sig->proto.proto[i] != 0);
    }

    DetectEngineCtxFree(de_ctx);

    PASS;
}

/**
 * \test DetectrotoTestSetup02 is a test for a icmpv4 and icmpv6
 *       protocol setting up in signature.
 */
static int DetectProtoTestSetup02(void)
{
    DetectProto dp;
    Signature *sig_icmpv4 = NULL;
    Signature *sig_icmpv6 = NULL;
    Signature *sig_icmp = NULL;
    DetectEngineCtx *de_ctx = NULL;

    memset(&dp, 0, sizeof(dp));

    FAIL_IF(DetectProtoInitTest(&de_ctx, &sig_icmpv4, &dp, "icmpv4") == 0);
    FAIL_IF(DetectProtoInitTest(&de_ctx, &sig_icmpv6, &dp, "icmpv6") == 0);
    FAIL_IF(DetectProtoInitTest(&de_ctx, &sig_icmp, &dp, "icmp") == 0);

    FAIL_IF_NOT(sig_icmpv4->proto.proto[IPPROTO_ICMP / 8] & (1 << (IPPROTO_ICMP % 8)));
    FAIL_IF_NOT(sig_icmpv6->proto.proto[IPPROTO_ICMPV6 / 8] & (1 << (IPPROTO_ICMPV6 % 8)));

    FAIL_IF_NOT(sig_icmp->proto.proto[IPPROTO_ICMP / 8] & (1 << (IPPROTO_ICMP % 8)));
    FAIL_IF_NOT(sig_icmp->proto.proto[IPPROTO_ICMPV6 / 8] & (1 << (IPPROTO_ICMPV6 % 8)));

    DetectEngineCtxFree(de_ctx);

    PASS;
}

/**
 * \test signature parsing with tcp-pkt and tcp-stream
 */

static int DetectProtoTestSig01(void)
{
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);

    de_ctx->flags |= DE_QUIET;

    Signature *s = DetectEngineAppendSig(
            de_ctx, "alert tcp-pkt any any -> any any (msg:\"tcp-pkt\"; content:\"blah\"; sid:1;)");
    FAIL_IF_NULL(s);

    s = DetectEngineAppendSig(de_ctx,
            "alert tcp-stream any any -> any any (msg:\"tcp-stream\"; content:\"blah\"; sid:2;)");
    FAIL_IF_NULL(s);

    DetectEngineCtxFree(de_ctx);

    PASS;
}
#endif /* UNITTESTS */

/**
 * \brief this function registers unit tests for DetectProto
 */
void DetectProtoTests(void)
{
#ifdef UNITTESTS
    UtRegisterTest("ProtoTestParse01", ProtoTestParse01);
    UtRegisterTest("ProtoTestParse02", ProtoTestParse02);
    UtRegisterTest("ProtoTestParse03", ProtoTestParse03);
    UtRegisterTest("ProtoTestParse04", ProtoTestParse04);
    UtRegisterTest("ProtoTestParse05", ProtoTestParse05);
    UtRegisterTest("ProtoTestParse06", ProtoTestParse06);
    UtRegisterTest("ProtoTestParse07", ProtoTestParse07);

    UtRegisterTest("DetectProtoTestSetup01", DetectProtoTestSetup01);
    UtRegisterTest("DetectProtoTestSetup02", DetectProtoTestSetup02);

    UtRegisterTest("DetectProtoTestSig01", DetectProtoTestSig01);
#endif /* UNITTESTS */
}

