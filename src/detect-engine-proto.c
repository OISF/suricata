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
 * \author Victor Julien <victor@inliniac.net>
 *
 * Proto part of the detection engine.
 *
 * \todo move this out of the detection plugin structure
 */

#include "suricata-common.h"

#include "decode.h"
#include "detect.h"

#include "app-layer-parser.h"

#include "flow-util.h"
#include "flow-var.h"

#include "detect-engine-siggroup.h"
#include "detect-engine-state.h"

#include "util-cidr.h"
#include "util-byte.h"
#include "util-unittest.h"
#include "util-unittest-helper.h"
#include "util-debug.h"

/**
 *  \brief   Function to initialize the protocol detection and
 *           allocate memory to the DetectProto structure.
 *
 *  \retval  DetectProto instance pointer if successful otherwise NULL
 */

DetectProto *DetectProtoInit(void)
{
    DetectProto *dp = SCMalloc(sizeof(DetectProto));
    if (unlikely(dp == NULL))
        return NULL;
    memset(dp,0,sizeof(DetectProto));

    return dp;
}

/**
 * \brief Free a DetectProto object
 *
 * \param dp Pointer to the DetectProto instance to be freed
 */
void DetectProtoFree(DetectProto *dp)
{
    if (dp == NULL)
        return;

    SCFree(dp);
}

/**
 * \brief Parses a protocol sent as a string.
 *
 * \param dp  Pointer to the DetectProto instance which will be updated with the
 *            incoming protocol information.
 * \param str Pointer to the string containing the protocol name.
 *
 * \retval >=0 If proto is detected, -1 otherwise.
 */
int DetectProtoParse(DetectProto *dp, char *str)
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
int DetectProtoContainsProto(DetectProto *dp, int proto)
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
#include "detect-engine-mpm.h"
/**
 * \brief this function is used to initialize the detection engine context and
 *        setup the signature with passed values.
 */
static int DetectProtoInitTest(DetectEngineCtx **de_ctx, Signature **sig,
                               DetectProto *dp, char *str)
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
    if (r < 0) {
        return 1;
    }

    SCLogDebug("DetectProtoParse should have rejected the \"6\" string");
    return 0;
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
    if (r >= 0 && dp.proto[(IPPROTO_TCP/8)] & (1<<(IPPROTO_TCP%8))) {
        return 1;
    }

    SCLogDebug("ProtoTestParse02: Error in parsing the \"tcp\" string");
    return 0;
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
    if (r >= 0 && dp.flags & DETECT_PROTO_ANY) {
        return 1;
    }

    SCLogDebug("ProtoTestParse03: Error in parsing the \"ip\" string");
    return 0;
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
    if (r < 0) {
        return 1;
    }

    SCLogDebug("ProtoTestParse04: it should not parsing the \"4242\" string");
    return 0;
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
    if (r < 0) {
        return 1;
    }

    SCLogDebug("ProtoTestParse05: it should not parsing the \"tcp/udp\" string");
    return 0;
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
    if (r < 0) {
        printf("parsing tcp-pkt failed: ");
        return 0;
    }

    if (!(dp.flags & DETECT_PROTO_ONLY_PKT)) {
        printf("DETECT_PROTO_ONLY_PKT flag not set: ");
        return 0;
    }

    return 1;
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
    if (r < 0) {
        printf("parsing tcp-stream failed: ");
        return 0;
    }

    if (!(dp.flags & DETECT_PROTO_ONLY_STREAM)) {
        printf("DETECT_PROTO_ONLY_STREAM flag not set: ");
        return 0;
    }

    return 1;
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
    int result = 0;
    int i;

    memset(&dp, 0, sizeof(dp));

    result = DetectProtoInitTest(&de_ctx, &sig, &dp, "tcp");
    if (result == 0) {
        goto end;
    }

    result = 0;

    /* The signature proto should be TCP */
    if (!(sig->proto.proto[(IPPROTO_TCP/8)] & (1<<(IPPROTO_TCP%8)))) {
         printf("failed in sig matching\n");
        goto cleanup;
    }
    for (i = 2; i < 256/8; i++) {
        if (sig->proto.proto[i] != 0) {
            printf("failed in sig clear\n");
            goto cleanup;
        }
    }

    result = 1;

cleanup:
    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
end:
    return result;
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
    int result = 0;
    int i;

    memset(&dp, 0, sizeof(dp));

    if (DetectProtoInitTest(&de_ctx, &sig_icmpv4, &dp, "icmpv4") == 0) {
        printf("failure - imcpv4.\n");
        goto end;
    }

    if (DetectProtoInitTest(&de_ctx, &sig_icmpv6, &dp, "icmpv6") == 0) {
        printf("failure - imcpv6.\n");
        goto end;
    }

    if (DetectProtoInitTest(&de_ctx, &sig_icmp, &dp, "icmp") == 0) {
        printf("failure - imcp.\n");
        goto end;
    }

    for (i = 0; i < 256 / 8; i++) {
        if (i == IPPROTO_ICMP) {
            if (!(sig_icmpv4->proto.proto[i / 8] & (1 << (i % 8)))) {
                printf("failed in sig matching - icmpv4 - icmpv4.\n");
                goto end;
            }
            continue;
        }
        if (sig_icmpv4->proto.proto[i / 8] & (1 << (i % 8))) {
            printf("failed in sig matching - icmpv4 - others.\n");
            goto end;
        }
    }

    for (i = 0; i < 256 / 8; i++) {
        if (i == IPPROTO_ICMPV6) {
            if (!(sig_icmpv6->proto.proto[i / 8] & (1 << (i % 8)))) {
                printf("failed in sig matching - icmpv6 - icmpv6.\n");
                goto end;
            }
            continue;
        }
        if (sig_icmpv6->proto.proto[i / 8] & (1 << (i % 8))) {
            printf("failed in sig matching - icmpv6 - others.\n");
            goto end;
        }
    }

    for (i = 0; i < 256 / 8; i++) {
        if (i == IPPROTO_ICMP || i == IPPROTO_ICMPV6) {
            if (!(sig_icmp->proto.proto[i / 8] & (1 << (i % 8)))) {
                printf("failed in sig matching - icmp - icmp.\n");
                goto end;
            }
            continue;
        }
        if (sig_icmpv6->proto.proto[i / 8] & (1 << (i % 8))) {
            printf("failed in sig matching - icmp - others.\n");
            goto end;
        }
    }

    result = 1;

 end:
    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

/**
 * \test DetectProtoTestSig01 is a test for checking the working of protocol
 *       detection by setting up the signature and later testing its working
 *       by matching the received packet against the sig.
 */

static int DetectProtoTestSig01(void)
{
    Packet *p = NULL;
    Signature *s = NULL;
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx;
    int result = 0;
    Flow f;

    memset(&f, 0, sizeof(Flow));
    memset(&th_v, 0, sizeof(th_v));

    FLOW_INITIALIZE(&f);

    p = UTHBuildPacket(NULL, 0, IPPROTO_TCP);

    p->flow = &f;
    p->flowflags |= FLOW_PKT_TOSERVER;
    p->flags |= PKT_HAS_FLOW;

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        goto end;
    }

    de_ctx->flags |= DE_QUIET;

    s = de_ctx->sig_list = SigInit(de_ctx,"alert udp any any -> any any "
            "(msg:\"Not tcp\"; flow:to_server; sid:1;)");

    if (s == NULL)
        goto end;

    s = s->next = SigInit(de_ctx,"alert ip any any -> any any "
            "(msg:\"IP\"; flow:to_server; sid:2;)");

    if (s == NULL)
        goto end;

    s = s->next = SigInit(de_ctx,"alert tcp any any -> any any "
            "(msg:\"TCP\"; flow:to_server; sid:3;)");

    if (s == NULL)
        goto end;

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    if (PacketAlertCheck(p, 1)) {
        printf("sid 1 alerted, but should not have: ");
        goto cleanup;
    } else if (PacketAlertCheck(p, 2) == 0) {
        printf("sid 2 did not alert, but should have: ");
        goto cleanup;
    } else if (PacketAlertCheck(p, 3) == 0) {
        printf("sid 3 did not alert, but should have: ");
        goto cleanup;
    }

    result = 1;

cleanup:
    FLOW_DESTROY(&f);

    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);

    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);

    UTHFreePackets(&p, 1);
end:
    return result;
}

/**
 * \test signature parsing with tcp-pkt and tcp-stream
 */

static int DetectProtoTestSig02(void)
{
    Signature *s = NULL;
    int result = 0;

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        goto end;
    }

    de_ctx->flags |= DE_QUIET;

    s = de_ctx->sig_list = SigInit(de_ctx,"alert tcp-pkt any any -> any any "
            "(msg:\"tcp-pkt\"; content:\"blah\"; sid:1;)");
    if (s == NULL) {
        printf("tcp-pkt sig parsing failed: ");
        goto end;
    }

    s = s->next = SigInit(de_ctx,"alert tcp-stream any any -> any any "
            "(msg:\"tcp-stream\"; content:\"blah\"; sid:2;)");
    if (s == NULL) {
        printf("tcp-pkt sig parsing failed: ");
        goto end;
    }

    result = 1;

end:
    if (de_ctx != NULL)
        DetectEngineCtxFree(de_ctx);
    return result;
}
#endif /* UNITTESTS */

/**
 * \brief this function registers unit tests for DetectProto
 */
void DetectProtoTests(void)
{
#ifdef UNITTESTS
    UtRegisterTest("ProtoTestParse01", ProtoTestParse01, 1);
    UtRegisterTest("ProtoTestParse02", ProtoTestParse02, 1);
    UtRegisterTest("ProtoTestParse03", ProtoTestParse03, 1);
    UtRegisterTest("ProtoTestParse04", ProtoTestParse04, 1);
    UtRegisterTest("ProtoTestParse05", ProtoTestParse05, 1);
    UtRegisterTest("ProtoTestParse06", ProtoTestParse06, 1);
    UtRegisterTest("ProtoTestParse07", ProtoTestParse07, 1);

    UtRegisterTest("DetectProtoTestSetup01", DetectProtoTestSetup01, 1);
    UtRegisterTest("DetectProtoTestSetup02", DetectProtoTestSetup02, 1);

    UtRegisterTest("DetectProtoTestSig01", DetectProtoTestSig01, 1);
    UtRegisterTest("DetectProtoTestSig02", DetectProtoTestSig02, 1);
#endif /* UNITTESTS */
}

